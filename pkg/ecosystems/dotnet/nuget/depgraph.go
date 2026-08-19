package nuget

import (
	"fmt"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManager = "nuget"

// buildEmptyDepGraph produces a dep graph containing only the root package.
//
// This is a placeholder: the resolver does not yet run `dotnet restore` or
// parse project.assets.json, so it has no dependencies to report. The graph is
// still well-formed, which lets the rest of the pipeline — result conversion,
// upload, and the platform — be exercised end to end before any resolution
// logic exists.
func buildEmptyDepGraph(rootName, rootVersion string) (*godepgraph.DepGraph, error) {
	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: pkgManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("creating dep graph builder: %w", err)
	}

	return builder.Build(), nil
}
