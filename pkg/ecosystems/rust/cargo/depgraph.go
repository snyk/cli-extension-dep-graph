package cargo

import (
	"fmt"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// buildDepGraph produces a Snyk dep graph rooted at out.RootID by walking
// out.Graph in DFS order. Nodes in stopAt are added as leaves: their incoming
// edge is connected, but the recursion does not descend into their subtree.
//
// stopAt is used for workspace member graphs to avoid duplicating the subtree
// of one member inside the graph of another. Pass an empty/nil map for the
// single-crate case.
func buildDepGraph(out *treeOutput, stopAt map[string]struct{}) (*godepgraph.DepGraph, error) {
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
		if err := addNode(builder, rootNodeID, childID, out.Graph, stopAt, visited); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// addNode adds id to the dep graph (if not already visited) and connects it
// to parentID. If id is in stopAt, its subtree is NOT walked — it appears as
// a leaf only. Recurses into each of id's forward dependencies otherwise.
//
// The visited map prevents infinite recursion on cycles (legitimate in Cargo
// via dev-deps; cargo tree emits `(*)` markers the parser treats as back-edges).
func addNode(
	builder *godepgraph.Builder,
	parentID, id string,
	forward forwardGraph,
	stopAt map[string]struct{},
	visited map[string]bool,
) error {
	if !visited[id] {
		visited[id] = true

		name, version := splitPkgID(id)
		builder.AddNode(id, &godepgraph.PkgInfo{Name: name, Version: version})

		if _, stop := stopAt[id]; !stop {
			for childID := range forward[id] {
				if err := addNode(builder, id, childID, forward, stopAt, visited); err != nil {
					return err
				}
			}
		}
	}

	if err := builder.ConnectNodes(parentID, id); err != nil {
		return fmt.Errorf("connecting %s → %s: %w", parentID, id, err)
	}

	return nil
}
