package bun

import (
	"fmt"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "bun"

// buildDepGraph constructs a Snyk dep graph from a whyGraph.
//
// rootName and rootVersion identify the root package (from package.json).
// directDepNames is the set of package names that are direct dependencies of the root;
// this seeds the DFS and naturally excludes dev-only packages when --dev is not set.
// graph is the parsed and inverted output of `bun why '*' --top`.
func buildDepGraph(rootName, rootVersion string, directDepNames map[pkgName]struct{}, graph *whyGraph) (*godepgraph.DepGraph, error) {
	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	rootNodeID := builder.GetRootNode().NodeID
	visited := make(map[pkg]bool)

	for name := range directDepNames {
		version, ok := graph.Packages[name]
		if !ok {
			// Package listed in package.json but not resolved — skip (e.g. workspace: protocol refs).
			continue
		}

		p := pkg{Name: name, Version: version}

		if err := addNode(builder, rootNodeID, p, graph.Dependencies, visited); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

// addNode adds p to the dep graph (if not already visited) and connects it to parentNodeID.
// It then recursively adds all of p's dependencies.
func addNode(
	builder *godepgraph.Builder,
	parentNodeID string,
	p pkg,
	deps depEdges,
	visited map[pkg]bool,
) error {
	if !visited[p] {
		visited[p] = true

		builder.AddNode(p.nodeID(), &godepgraph.PkgInfo{Name: string(p.Name), Version: string(p.Version)})

		for dep := range deps[p] {
			if err := addNode(builder, p.nodeID(), dep, deps, visited); err != nil {
				return err
			}
		}
	}

	if err := builder.ConnectNodes(parentNodeID, p.nodeID()); err != nil {
		return fmt.Errorf("connecting %s → %s: %w", parentNodeID, p.nodeID(), err)
	}

	return nil
}
