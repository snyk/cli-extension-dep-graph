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
func BuildDepGraph(
	rootName, rootVersion string,
	directDeps map[string]string,
	pkgMap map[string]*ResolvedPackage,
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

// BuildDepGraphFromWhyGraph constructs a dep graph using bun why output for
// accurate transitive resolution.
//
// directDeps is the set of package names that are direct dependencies of the root
// (workspace: protocol entries are silently skipped as they are absent from AllPkgs).
func BuildDepGraphFromWhyGraph(
	rootName, rootVersion string,
	directDeps map[string]bool,
	graph *WhyGraph,
) (*godepgraph.DepGraph, error) {
	// Invert the reverse adjacency to obtain the forward adjacency:
	// forwardAdj["pkg@ver"] = set of "dep@ver" that pkg directly depends on.
	forwardAdj := make(map[string]map[string]struct{}, len(graph.ReverseAdj))
	for pkg, dependents := range graph.ReverseAdj {
		for dep := range dependents {
			if forwardAdj[dep] == nil {
				forwardAdj[dep] = make(map[string]struct{})
			}

			forwardAdj[dep][pkg] = struct{}{}
		}
	}

	builder, err := godepgraph.NewBuilder(
		&godepgraph.PkgManager{Name: packageManager},
		&godepgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create dep graph builder: %w", err)
	}

	visited := make(map[string]bool)
	rootNodeID := builder.GetRootNode().NodeID

	for name := range directDeps {
		version, ok := graph.AllPkgs[name]
		if !ok {
			continue
		}

		nodeID := nodeIDFor(name, version)

		if err := addFromWhyGraph(builder, rootNodeID, nodeID, forwardAdj, visited); err != nil {
			return nil, err
		}
	}

	return builder.Build(), nil
}

func addFromWhyGraph(
	builder *godepgraph.Builder,
	parentNodeID, nodeID string,
	forwardAdj map[string]map[string]struct{},
	visited map[string]bool,
) error {
	if !visited[nodeID] {
		visited[nodeID] = true

		name, version := parseNameVersion(nodeID)
		builder.AddNode(nodeID, &godepgraph.PkgInfo{Name: name, Version: version})

		for depNodeID := range forwardAdj[nodeID] {
			if err := addFromWhyGraph(builder, nodeID, depNodeID, forwardAdj, visited); err != nil {
				return err
			}
		}
	}

	if err := builder.ConnectNodes(parentNodeID, nodeID); err != nil {
		return fmt.Errorf("failed to connect %s → %s: %w", parentNodeID, nodeID, err)
	}

	return nil
}

// FilterWorkspaceDeps removes workspace: protocol references from a dep map so
// they are not looked up in pkgMap (they have no entry there).
func FilterWorkspaceDeps(deps map[string]string) map[string]string {
	filtered := make(map[string]string, len(deps))
	for k, v := range deps {
		if !strings.HasPrefix(v, workspaceProtocol) {
			filtered[k] = v
		}
	}
	return filtered
}
