package cargo

import (
	"fmt"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// buildDepGraph produces a Snyk dep graph rooted at out.RootID by walking
// out.Graph in DFS order.
//
// Workspace support (one graph per member crate, stop-at-leaf at other
// members) lands in a later commit alongside cargo metadata integration.
func buildDepGraph(out *treeOutput) (*godepgraph.DepGraph, error) {
	rootName, rootVersion := splitPkgID(out.RootID)

	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID
	visited := make(map[string]bool)

	for childID := range out.Graph[out.RootID] {
		if err := addNode(builder, rootNodeID, childID, out.Graph, visited); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// addNode adds id to the dep graph (if not already visited) and connects it
// to parentID. Recurses into each of id's forward dependencies. The visited
// map prevents infinite recursion on cycles (legitimate in Cargo via
// dev-deps; cargo tree emits `(*)` markers the parser treats as back-edges).
func addNode(
	builder *godepgraph.Builder,
	parentID, id string,
	forward forwardGraph,
	visited map[string]bool,
) error {
	if !visited[id] {
		visited[id] = true

		name, version := splitPkgID(id)
		builder.AddNode(id, &godepgraph.PkgInfo{Name: name, Version: version})

		for childID := range forward[id] {
			if err := addNode(builder, id, childID, forward, visited); err != nil {
				return err
			}
		}
	}

	if err := builder.ConnectNodes(parentID, id); err != nil {
		return fmt.Errorf("connecting %s → %s: %w", parentID, id, err)
	}

	return nil
}
