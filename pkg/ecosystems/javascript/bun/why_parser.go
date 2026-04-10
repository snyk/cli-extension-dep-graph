package bun

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var (
	// rootLineRe matches a package header line (no leading whitespace).
	//
	// Group 1: package name (may be scoped, e.g. "@types/node").
	// Group 2: resolved version (empty string marks the root project placeholder).
	//
	// Examples:
	//   "debug@4.4.3"                                      → ["debug", "4.4.3"]
	//   "@types/node@25.5.2"                               → ["@types/node", "25.5.2"]
	//   "@workspace/logger@workspace:packages/logger"       → ["@workspace/logger", "workspace:packages/logger"]
	//   "my-app@"                                          → ["my-app", ""]  (root project, skipped)
	rootLineRe = regexp.MustCompile(`^(@?[^@\s]+)@(\S*)$`)

	// depth1LineRe matches a direct-dependent line produced by `bun why '*' --top`.
	//
	// Format: "  [└├]─ [dev |peer |optional ]name@version[ (requires ...)]"
	//
	// Group 1: "name@version" of the dependent package.
	//   Root project references (e.g. "my-app (requires ^4)") have no version component,
	//   so they never match — they are silently skipped.
	depth1LineRe = regexp.MustCompile(`^  [└├]─ (?:dev |peer |optional )?(@?[^@\s(]+@\S+?)(?:\s+\(requires[^)]+\))?$`)
)

// parseWhyOutput parses the text output of `bun why '*' --top` into a whyGraph.
// It reads from r as a stream, so the caller need not buffer the full output first.
//
// The output is a reverse-dependency tree: each root entry is a resolved package,
// and its depth-1 children are its direct dependents (parents). We invert this
// into a forward adjacency map during parsing so callers can walk dependencies
// in the natural direction (from dependent to dependency).
func parseWhyOutput(r io.Reader) (*whyGraph, error) {
	// reverseAdj[dep] = set of packages that directly depend on dep.
	reverseAdj := make(depEdges)
	packages := make(pkgRegistry)

	scanner := bufio.NewScanner(r)

	var currentPkg *pkg

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Depth-1 lines always start with "  └─" or "  ├─"; check them first
		// since they are more common than root lines.
		depth1Match := depth1LineRe.FindStringSubmatch(line)
		if depth1Match != nil {
			if currentPkg == nil {
				return nil, fmt.Errorf("current package is nil, but found depth-1 line: %s", line)
			}

			dependent, ok := parsePackageID(depth1Match[1])
			if !ok {
				continue
			}

			reverseAdj[*currentPkg].add(dependent)
			continue
		}

		// Root package line: "name@version" with no leading whitespace.
		rootMatch := rootLineRe.FindStringSubmatch(line)
		if rootMatch == nil {
			continue
		}

		name, version := pkgName(rootMatch[1]), pkgVersion(rootMatch[2])
		if version == "" {
			// Trailing "@" with no version is bun's marker for the root project — skip it.
			currentPkg = nil

			continue
		}

		p := pkg{Name: name, Version: version}
		currentPkg = &p
		packages[name] = version
		reverseAdj[*currentPkg] = make(pkgSet)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning bun why output: %w", err)
	}

	// Invert reverseAdj → dependencies.
	// reverseAdj[dep] = {dependents}  →  dependencies[dependent] = {deps}
	dependencies := make(depEdges, len(reverseAdj))
	for dep, dependents := range reverseAdj {
		for dependent := range dependents {
			// Workspace version normalisation is applied here, after the full packages
			// registry is built, because bun why truncates workspace versions in
			// depth-1 lines: the root entry shows "pkg@workspace:packages/x" but the
			// dependent entry shows "pkg@workspace". The truncated form can arrive
			// before the canonical root line (bun outputs alphabetically), so the fix
			// must run as a post-pass once all canonical versions are known.
			if canonical, exists := packages[dependent.Name]; exists {
				if strings.HasPrefix(string(canonical), string(dependent.Version)+":") {
					dependent.Version = canonical
				}
			}

			if dependencies[dependent] == nil {
				dependencies[dependent] = make(pkgSet)
			}

			dependencies[dependent].add(dep)
		}
	}

	return &whyGraph{
		Packages:     packages,
		Dependencies: dependencies,
	}, nil
}

// parsePackageID parses a "name@version" node ID string into a pkg.
// Returns (pkg{}, false) when s does not match the expected format.
// Handles scoped packages (e.g. "@types/node@1.2.3") via rootLineRe.
func parsePackageID(s string) (pkg, bool) {
	m := rootLineRe.FindStringSubmatch(s)
	if m == nil {
		return pkg{}, false
	}

	return pkg{Name: pkgName(m[1]), Version: pkgVersion(m[2])}, true
}
