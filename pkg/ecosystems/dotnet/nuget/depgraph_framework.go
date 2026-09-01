package nuget

import (
	"fmt"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// buildFrameworkDepGraph builds the dep graph for a packages.config project,
// mirroring snyk-nuget-plugin's dotnet-framework-parser.
//
// Every package is a direct dependency of the root, whether the project asked
// for it or something it depends on did. That is upstream's shape, and it is
// inherent to the format: a .NET Framework manifest is a flattened list with no
// record of who pulled what in.
func buildFrameworkDepGraph(
	rootName, rootVersion string,
	installed *packageSet,
) (*godepgraph.DepGraph, error) {
	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	edges := newEdgeSet(builder)
	rootNodeID := builder.GetRootNode().NodeID

	for _, pkg := range installed.packages {
		nodeID := pkgNodeID(pkg.name, pkg.version)

		builder.AddNode(nodeID, &godepgraph.PkgInfo{Name: pkg.name, Version: pkg.version})

		if err := edges.connect(rootNodeID, nodeID); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}
