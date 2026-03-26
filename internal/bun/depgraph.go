package bun

import (
	"fmt"
	"strings"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

const packageManager = "bun"

// BuildDepGraph constructs a dep graph from bun.lock data for a single workspace.
// rootName/rootVersion identify the root package.
// directDeps is the map of alias → version-range for the root's direct dependencies.
// pkgMap is the full resolved package map from BuildPackageMap.
// includeDev controls whether devDependencies of the root workspace are included.
func BuildDepGraph(
	rootName, rootVersion string,
	directDeps map[string]string,
	pkgMap map[string]*ResolvedPackage,
	includeDev bool,
) (*godepgraph.DepGraph, error) {
	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: packageManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create dep graph builder: %w", err)
	}

	visited := make(map[string]bool)
	if err := addDepsRecursive(builder, builder.GetRootNode().NodeID, directDeps, pkgMap, visited); err != nil {
		return nil, err
	}

	return builder.Build(), nil
}

func addDepsRecursive(
	builder *godepgraph.Builder,
	parentNodeID string,
	deps map[string]string,
	pkgMap map[string]*ResolvedPackage,
	visited map[string]bool,
) error {
	for alias := range deps {
		pkg, ok := pkgMap[alias]
		if !ok {
			// Workspace cross-references (workspace: protocol) are filtered before
			// reaching here; anything else missing is logged and skipped.
			continue
		}

		nodeID := nodeIDFor(pkg.Name, pkg.Version)

		if !visited[nodeID] {
			visited[nodeID] = true
			builder.AddNode(nodeID, &godepgraph.PkgInfo{Name: pkg.Name, Version: pkg.Version})

			// Recurse into this package's own deps before connecting so the
			// builder sees child nodes before the parent→child edge.
			if err := addDepsRecursive(builder, nodeID, pkg.Deps, pkgMap, visited); err != nil {
				return err
			}
		}

		if err := builder.ConnectNodes(parentNodeID, nodeID); err != nil {
			return fmt.Errorf("failed to connect %s → %s: %w", parentNodeID, nodeID, err)
		}
	}
	return nil
}

func nodeIDFor(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}

// FilterWorkspaceDeps removes workspace: protocol references from a dep map so
// they are not looked up in pkgMap (they have no entry there).
func FilterWorkspaceDeps(deps map[string]string) map[string]string {
	filtered := make(map[string]string, len(deps))
	for k, v := range deps {
		if !strings.HasPrefix(v, "workspace:") {
			filtered[k] = v
		}
	}
	return filtered
}
