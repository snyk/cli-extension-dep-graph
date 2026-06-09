package cargo

import "strings"

// forwardGraph maps each full package ID ("name@version") to the set of package
// IDs it directly depends on, as produced by `cargo tree --no-dedupe`.
//
// Because cargo tree prints in parent-to-child order, we store forward edges
// directly rather than inverting from a reverse adjacency (bun's why-output
// shape).
type forwardGraph map[string]map[string]struct{}

// treeOutput is the parsed result of one `cargo tree` invocation.
type treeOutput struct {
	// RootID is the depth-0 package — the crate being analyzed.
	RootID string

	// Graph is the forward adjacency: Graph[A] = {B, C} means A depends on B and C.
	Graph forwardGraph
}

// splitPkgID splits a full package ID ("name@version") at the last '@' that is
// not at position 0, returning the bare name and resolved version separately.
// Used to populate PkgInfo{Name, Version} in the dep-graph builder.
//
// Examples:
//
//	"serde@1.0.193"          → ("serde", "1.0.193")
//	"proc-macro2@1.0.70"     → ("proc-macro2", "1.0.70")
func splitPkgID(id string) (name, version string) {
	i := strings.LastIndex(id, "@")
	if i <= 0 {
		return id, ""
	}

	return id[:i], id[i+1:]
}
