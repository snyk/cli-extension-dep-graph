package modules

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const (
	pkgManager     = "gomodules"
	defaultVersion = "0.0.0"
	rootNodeID     = "root-node"
	stdlibPrefix   = "std/"
	unknownVersion = "unknown"
)

// rePseudoVersion matches Go module pseudo-versions, e.g.
// `v0.0.0-20240101120000-abcdef012345`. The capture groups isolate the
// 12-char short revision hash that the legacy plugin uses as the
// Snyk-side version (prefixed with '#').
var rePseudoVersion = regexp.MustCompile(`v\d+\.\d+\.\d+-(?:.*?)\d{14}-([0-9a-f]{12})`)

// GraphOptions controls how `go list` output is translated into a
// dep-graph. Defaults match the legacy snyk-go-plugin's behaviour as
// it's invoked from the Snyk CLI today (see
// cli/src/lib/plugins/build-plugin-options.ts).
type GraphOptions struct {
	// IncludeStdlib synthesises std/<pkg> nodes for direct stdlib
	// imports. Default false: stdlib packages are dropped.
	// Controlled in the CLI by the
	// includeGoStandardLibraryDeps feature flag.
	IncludeStdlib bool

	// UseReplaceName makes the resolver substitute the replaced
	// module's path into the package name when a `replace` directive
	// is in effect. Hardcoded true in the CLI shim today; we default
	// to true to match.
	UseReplaceName bool

	// StdlibVersion sets the synthetic version attached to std/<pkg>
	// nodes. Defaults to "unknown" — the CLI populates this from
	// `go version` output when the include-stdlib flag is on.
	StdlibVersion string
}

// parseGoListOutput consumes the concatenated `go list -json` stream
// emitted on stdout and returns one GoListPackage per object. The
// objects are NOT a JSON array, so we drive a streaming decoder.
func parseGoListOutput(r io.Reader) ([]GoListPackage, error) {
	dec := json.NewDecoder(r)
	var pkgs []GoListPackage
	for {
		var p GoListPackage
		if err := dec.Decode(&p); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decoding go list JSON: %w", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// buildDepGraph translates a slice of `go list -json -deps` records
// into a Snyk dep graph rooted at the project's main module.
//
// Behavior mirrors snyk-go-plugin/lib/dep-graph.ts:
//
//   - Root identity comes from the first non-DepOnly package whose
//     Module.Main is true. Falls back to the caller-supplied
//     fallbackRoot if no such package is found (e.g. when `go list`
//     can't determine the main module).
//   - Direct top-level deps are the union of `Imports` from every
//     non-DepOnly package.
//   - Standard-library packages are dropped unless options.IncludeStdlib;
//     when included they appear as synthetic `std/<importpath>` nodes
//     under whichever package imports them.
//   - Cycle handling matches the legacy implementation: if the recursion
//     would revisit a node already on the path (ancestor or sibling-
//     child of the current parent), we drop the edge; if the node was
//     visited earlier on this branch, we attach a pruned-leaf marker
//     instead of recursing.
func buildDepGraph(pkgs []GoListPackage, fallbackRoot string, options GraphOptions) (*godepgraph.DepGraph, error) {
	packagesByName := make(map[string]GoListPackage, len(pkgs))
	for _, p := range pkgs {
		packagesByName[p.ImportPath] = p
	}

	rootName := fallbackRoot
	for _, p := range pkgs {
		if p.DepOnly {
			continue
		}
		if p.Module != nil && p.Module.Main && p.Module.Path != "" {
			rootName = p.Module.Path
			break
		}
	}
	if rootName == "" {
		rootName = fallbackRoot
	}

	rootPkg := makePkgInfo(rootName, defaultVersion, nil, options)

	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		rootPkg,
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	topLevel := extractTopLevelImports(pkgs)

	childrenChain := make(map[string][]string)
	ancestorsChain := make(map[string][]string)
	if err := walk(builder, topLevel, packagesByName, rootNodeID, childrenChain, ancestorsChain, options, nil); err != nil {
		return nil, err
	}

	return builder.Build(), nil
}

// walk mirrors buildGraph() in snyk-go-plugin/lib/dep-graph.ts.
//
// The TS code iterates the children list in reverse order; we preserve
// that for byte-for-byte equivalence on graphs where order changes the
// outcome of the cycle-detection heuristics (rare in practice but
// observed in the legacy fixture corpus).
func walk(
	builder *godepgraph.Builder,
	depPackages []string,
	packagesByName map[string]GoListPackage,
	currentParent string,
	childrenChain map[string][]string,
	ancestorsChain map[string][]string,
	options GraphOptions,
	visited map[string]bool,
) error {
	for i := len(depPackages) - 1; i >= 0; i-- {
		localVisited := visited
		if localVisited == nil {
			localVisited = make(map[string]bool)
		}

		packageImport := depPackages[i]
		pkg, found := packagesByName[packageImport]

		// Standard library handling.
		if found && pkg.Standard {
			if !options.IncludeStdlib {
				continue
			}
			stdName := stdlibPrefix + packageImport
			node := makeStdlibPkgInfo(stdName, options)
			builder.AddNode(stdName, node)
			if err := builder.ConnectNodes(currentParent, stdName); err != nil {
				return fmt.Errorf("connecting stdlib %s: %w", stdName, err)
			}
			continue
		}

		// Skip local (root-module) packages: we walk through them via
		// the top-level Imports collection but they never become nodes.
		if !found || !pkg.DepOnly {
			continue
		}

		if currentParent == "" || packageImport == "" {
			continue
		}

		var modulePtr *GoModule
		if pkg.Module != nil {
			m := *pkg.Module
			modulePtr = &m
		}

		currentChildren := childrenChain[currentParent]
		currentAncestors := ancestorsChain[currentParent]

		// Cycle break: drop the edge if this dep is the current
		// parent itself, a sibling already added under the parent, or
		// an ancestor of the current parent.
		if packageImport == currentParent ||
			containsString(currentChildren, packageImport) ||
			containsString(currentAncestors, packageImport) {
			continue
		}

		newNode := makePkgInfo(packageImport, unknownVersion, modulePtr, options)

		if localVisited[packageImport] {
			prunedID := packageImport + ":pruned"
			builder.AddNode(prunedID, newNode, godepgraph.WithNodeInfo(&godepgraph.NodeInfo{Labels: map[string]string{"pruned": "true"}}))
			if err := builder.ConnectNodes(currentParent, prunedID); err != nil {
				return fmt.Errorf("connecting pruned %s: %w", prunedID, err)
			}
			continue
		}

		builder.AddNode(packageImport, newNode)
		if err := builder.ConnectNodes(currentParent, packageImport); err != nil {
			return fmt.Errorf("connecting %s: %w", packageImport, err)
		}
		localVisited[packageImport] = true

		childrenChain[currentParent] = append(currentChildren, packageImport)
		ancestorsChain[packageImport] = append(currentAncestors, currentParent)

		transitives := packagesByName[packageImport].Imports
		if len(transitives) > 0 {
			if err := walk(builder, transitives, packagesByName, packageImport, childrenChain, ancestorsChain, options, localVisited); err != nil {
				return err
			}
		}
	}
	return nil
}

// extractTopLevelImports collects every distinct import seen across
// every non-DepOnly package. This mirrors the legacy plugin's
// extractAllImports() — it intentionally surfaces all packages reachable
// from the project's own code, not just root-module-level imports.
func extractTopLevelImports(pkgs []GoListPackage) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, p := range pkgs {
		for _, imp := range p.Imports {
			if _, ok := seen[imp]; ok {
				continue
			}
			seen[imp] = struct{}{}
			out = append(out, imp)
		}
	}
	return out
}

// makePkgInfo builds a PkgInfo for a non-stdlib package. When a Replace
// directive is present and UseReplaceName is on, the package name has
// the original module path swapped for the replacement path; the
// version is always taken from the replacement (regardless of
// UseReplaceName, matching legacy).
func makePkgInfo(name, version string, mod *GoModule, options GraphOptions) *godepgraph.PkgInfo {
	if mod == nil {
		return &godepgraph.PkgInfo{Name: name, Version: version}
	}

	snykName := name
	snykVersion := version

	if mod.Version != "" {
		snykVersion = toSnykVersion(mod.Version)
	}

	if mod.Replace != nil {
		if options.UseReplaceName && mod.Path != "" {
			snykName = strings.Replace(name, mod.Path, mod.Replace.Path, 1)
		}
		snykVersion = toSnykVersion(mod.Replace.Version)
	}

	return &godepgraph.PkgInfo{Name: snykName, Version: snykVersion}
}

// makeStdlibPkgInfo builds the PkgInfo for a synthetic stdlib node.
func makeStdlibPkgInfo(name string, options GraphOptions) *godepgraph.PkgInfo {
	v := options.StdlibVersion
	if v == "" {
		v = unknownVersion
	}
	return &godepgraph.PkgInfo{Name: name, Version: v}
}

// toSnykVersion converts a Go module version string to the Snyk-side
// representation used by the legacy plugin:
//   - pseudo-versions collapse to "#<12-char-revision>"
//   - exact versions drop the leading "v" and any "+incompatible"
//     suffix
func toSnykVersion(v string) string {
	if v == "" {
		return ""
	}
	if m := rePseudoVersion.FindStringSubmatch(v); m != nil {
		return "#" + m[1]
	}
	v = strings.TrimSuffix(v, "+incompatible")
	v = strings.TrimPrefix(v, "v")
	return v
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
