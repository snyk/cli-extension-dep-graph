package bun

// reverseGraph maps each full package ID ("name@version") to the set of package IDs
// that directly depend on it, as produced by `bun why '*' --top`.
//
// Root-project dependency lines are excluded: depth-1 lines whose dependent has
// no @version token are detected as root-direct deps and stored in whyOutput.ProdDeps
// or whyOutput.DevDeps instead.
//
// Multiple versions of the same package name appear as distinct keys
// (e.g. "ms@2.0.0" and "ms@3.0.0" can both be present).
type reverseGraph map[string]map[string]struct{}

// whyOutput is the parsed result of `bun why '*' --top`.
type whyOutput struct {
	// Graph is the full reverse-adjacency representation of the installed package graph.
	Graph reverseGraph

	// ProdDeps is the list of package IDs directly depended on by the root project
	// as production, optional, or peer dependencies.
	ProdDeps []string

	// DevDeps is the list of package IDs directly depended on by the root project
	// as dev dependencies.
	DevDeps []string
}
