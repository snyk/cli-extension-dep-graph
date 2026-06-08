package bundler

import (
	"errors"
	"fmt"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const (
	pkgManagerName = "rubygems"
	// bundlerGemName is omitted from every dep graph: the @snyk/gemfile
	// reference parser silently drops it because bundler is not listed
	// in any source block's `specs:` (it's the runner itself, not a
	// dependency). We replicate that omission and additionally skip the
	// DEPENDENCIES entry so it never appears as a missing-spec edge.
	bundlerGemName = "bundler"
)

// CycleError is returned when a dependency cycle is detected while
// walking the resolved specs. The legacy parser threw a 422 with the
// offending gem and ancestor chain; we keep the same shape.
type CycleError struct {
	Gem   string
	Chain []string
}

func (e *CycleError) Error() string {
	return fmt.Sprintf("cyclic dependency detected in lockfile at %q (chain: %v)", e.Gem, e.Chain)
}

// BuildDepGraph constructs a Snyk dep graph from a parsed Lockfile.
//
// Behavior, matching the legacy plugin's Gemfile.lock-to-dependencies
// conversion:
//   - The root is rootName/rootVersion (caller-supplied; typically
//     basename(projectDir) for a plain Gemfile, or the gemspec
//     name+version for a .gemspec project).
//   - The root's direct deps are the entries from DEPENDENCIES, in
//     lockfile order, after stripping the `!` marker.
//   - "bundler" is omitted as a root dep AND, defensively, as a child
//     of any other spec — matching the legacy "if (gemspec) { ... }"
//     guard that silently skipped specs not present in the resolved
//     map.
//   - A spec listed in DEPENDENCIES but missing from the source blocks
//     is skipped (legacy behavior — keeps the graph buildable).
//   - Cycles raise CycleError, matching legacy 422 semantics.
func BuildDepGraph(rootName, rootVersion string, lf *Lockfile) (*godepgraph.DepGraph, error) {
	return BuildDepGraphWithOptions(rootName, rootVersion, lf, BuildOptions{})
}

// BuildOptions tweaks dep-graph construction beyond the legacy defaults.
//
// IncludeDev is a deliberate enhancement over legacy: bundler's Gemfile
// has `group :development do ... end` blocks, but the resolved
// Gemfile.lock does NOT encode which group a gem belongs to. Group info
// is only knowable by re-parsing the (lossy) Gemfile, which we don't
// have here. For now IncludeDev is wired but has no behavioral effect;
// the plugin layer exposes it so when we later parse the Gemfile (or
// switch to a richer lockfile format), no plumbing churn is needed.
//
// See the migration plan section "Group semantics — --dev behavior".
type BuildOptions struct {
	IncludeDev bool
}

// BuildDepGraphWithOptions is the option-aware variant of BuildDepGraph.
func BuildDepGraphWithOptions(rootName, rootVersion string, lf *Lockfile, opts BuildOptions) (*godepgraph.DepGraph, error) {
	if lf == nil {
		return nil, errors.New("bundler.BuildDepGraph: nil lockfile")
	}
	if rootName == "" {
		return nil, errors.New("bundler.BuildDepGraph: empty rootName")
	}

	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManagerName},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID

	// visited records the set of (name) currently on the DFS stack —
	// used for cycle detection. Distinct from `added`, which is whether
	// a node already exists in the graph (and may be reconnected).
	visited := make(map[string]bool)
	added := make(map[string]bool)

	for _, dep := range lf.Dependencies {
		// Skip bundler in DEPENDENCIES (legacy: silently dropped because
		// it's not in specs). Also a no-op IncludeDev gate placeholder —
		// see BuildOptions doc.
		if dep.Name == bundlerGemName {
			continue
		}
		if err := walk(builder, rootNodeID, dep.Name, lf, visited, added, []string{rootName}); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// walk performs a DFS from `name`, adding nodes/edges to builder and
// raising CycleError if `name` is already on the current ancestor chain.
//
// Specs not present in lf.Specs (e.g. bundler, or a missing/corrupt
// lockfile entry) are silently skipped — matches legacy
// "if (gemspec) { ... }" guard.
func walk(
	builder *godepgraph.Builder,
	parentNodeID, name string,
	lf *Lockfile,
	visited, added map[string]bool,
	chain []string,
) error {
	spec, ok := lf.Specs[name]
	if !ok {
		// Legacy: just ignore — better than crashing.
		return nil
	}

	if visited[name] {
		return &CycleError{Gem: name, Chain: append([]string(nil), chain...)}
	}

	nodeID := name + "@" + spec.Version

	if !added[name] {
		added[name] = true
		visited[name] = true

		builder.AddNode(nodeID, &godepgraph.PkgInfo{Name: name, Version: spec.Version})

		for _, child := range spec.Children {
			if child == bundlerGemName {
				// Defensive: should never appear as a child, but legacy
				// would also silently drop it if it did.
				continue
			}
			if err := walk(builder, nodeID, child, lf, visited, added, append(chain, name)); err != nil {
				return err
			}
		}

		visited[name] = false
	}

	if err := builder.ConnectNodes(parentNodeID, nodeID); err != nil {
		return fmt.Errorf("connecting %s → %s: %w", parentNodeID, nodeID, err)
	}
	return nil
}
