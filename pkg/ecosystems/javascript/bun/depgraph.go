package bun

import (
	"fmt"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "bun"

// buildDepGraph constructs a Snyk dep graph from a whyOutput.
//
// All packages in out.ProdDeps and out.DevDeps are included as seeds.
// The dep graph is built by inverting the reverse-adjacency in out.Graph into
// a forward adjacency and performing a DFS from each seed.
func buildDepGraph(
	rootName, rootVersion string,
	out *whyOutput,
) (*godepgraph.DepGraph, error) {
	// Seed from all root-direct deps — both prod and dev.
	seeds := make(map[string]struct{}, len(out.ProdDeps)+len(out.DevDeps))
	for _, id := range out.ProdDeps {
		seeds[id] = struct{}{}
	}
	for _, id := range out.DevDeps {
		seeds[id] = struct{}{}
	}

	// Build forward adjacency by inverting the reverse graph.
	// out.Graph[id] = set of packages that depend on id
	// → forward[dep] = set of packages that dep depends on
	forward := make(map[string]map[string]struct{}, len(out.Graph))
	for id, dependents := range out.Graph {
		if forward[id] == nil {
			forward[id] = make(map[string]struct{})
		}

		for dep := range dependents {
			// dep depends on id → forward edge: dep → id
			if forward[dep] == nil {
				forward[dep] = make(map[string]struct{})
			}

			forward[dep][id] = struct{}{}
		}
	}

	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID
	visited := make(map[string]bool)

	for id := range seeds {
		if err := addNode(builder, rootNodeID, id, forward, visited); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// addNode adds id to the dep graph (if not already visited) and connects it to parentID.
// It then recursively adds all of id's forward dependencies.
func addNode(
	builder *godepgraph.Builder,
	parentID, id string,
	forward map[string]map[string]struct{},
	visited map[string]bool,
) error {
	if !visited[id] {
		visited[id] = true

		name, version := splitPkgID(id)
		builder.AddNode(id, &godepgraph.PkgInfo{Name: name, Version: version})

		for dep := range forward[id] {
			if err := addNode(builder, id, dep, forward, visited); err != nil {
				return err
			}
		}
	}

	// Connect parentID → id even when id was already visited: the same node
	// may be reachable from multiple parents, each requiring its own edge.
	if err := builder.ConnectNodes(parentID, id); err != nil {
		return fmt.Errorf("connecting %s → %s: %w", parentID, id, err)
	}

	return nil
}

// splitPkgID splits a full package ID ("name@version") at the last '@' that is
// not at position 0, returning the bare name and resolved version separately.
// This is used only to satisfy the Snyk dep graph builder's PkgInfo{Name, Version}.
//
// Examples:
//
//	"ms@2.0.0"                                    → ("ms", "2.0.0")
//	"@types/node@25.5.2"                          → ("@types/node", "25.5.2")
//	"@workspace/logger@workspace:packages/logger" → ("@workspace/logger", "workspace:packages/logger")
func splitPkgID(id string) (name, version string) {
	i := strings.LastIndex(id, "@")
	if i <= 0 {
		return id, ""
	}

	return id[:i], id[i+1:]
}

