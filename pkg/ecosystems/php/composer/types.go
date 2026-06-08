package composer

// parsedOutput is the intermediate representation produced by parseTreeOutput
// before being handed to the dep-graph builder. It captures the forward
// adjacency graph keyed by canonical "name@version" IDs plus the list of
// direct dependencies of the root project.
//
// Composer's `show --locked --tree` emits one top-level subtree per direct
// dependency of the root project. The root itself is not represented as a
// node in the output — we reconstruct it from composer.json's name field
// (with directory-name fallback) and attach the parsed top-level subtrees
// as its direct deps.
type parsedOutput struct {
	// Graph maps a package ID ("name@version") to the set of IDs it depends
	// on. Empty value means "leaf in the tree as printed by composer".
	Graph map[string]map[string]struct{}

	// RootDeps is the ordered list of top-level IDs that the root project
	// depends on (deduplicated). Order is preserved for deterministic graph
	// construction, which keeps goldens stable across runs.
	RootDeps []string
}

// newParsedOutput returns an empty parsedOutput ready to be populated.
func newParsedOutput() *parsedOutput {
	return &parsedOutput{
		Graph:    make(map[string]map[string]struct{}),
		RootDeps: nil,
	}
}
