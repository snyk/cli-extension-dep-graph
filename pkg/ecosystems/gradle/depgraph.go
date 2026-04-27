package gradle

import (
	"fmt"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

const pkgManagerName = "gradle"

// buildDepGraph converts a single gradleProject into a *depgraph.DepGraph by
// merging the resolved dependencies from all available configurations.
func buildDepGraph(proj *gradleProject) (*depgraph.DepGraph, error) {
	// Derive a stable root name (group:artifact) and version from the GAV.
	rootName, rootVersion := splitGAV(proj.GAV)
	if rootName == "" {
		rootName = proj.Name
	}
	if rootVersion == "" {
		rootVersion = proj.Version
	}
	if rootVersion == "unspecified" {
		rootVersion = ""
	}

	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: pkgManagerName},
		&depgraph.PkgInfo{Name: rootName, Version: rootVersion},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create dep-graph builder for project %s: %w", proj.Path, err)
	}

	rootNodeID := builder.GetRootNode().NodeID

	// Merge all configurations into a single graph.  Per-configuration
	// filtering (e.g. --configuration-matching, preferring runtimeClasspath)
	// will be added when feature parity work begins.
	for _, cfg := range proj.Configurations {
		if cfg.Error != "" {
			continue
		}
		seen := make(map[string]bool) // Fresh seen map per configuration
		for _, dep := range cfg.Root.Dependencies {
			if err := addDep(builder, dep, rootNodeID, seen); err != nil {
				return nil, fmt.Errorf("project %s: %w", proj.Path, err)
			}
		}
	}

	return builder.Build(), nil
}

// addDep recursively adds a resolved dependency node and its children to the builder.
// Circular dependencies (already present in seen) are added as pruned leaf nodes.
func addDep(builder *depgraph.Builder, dep gradleDep, parentID string, seen map[string]bool) error {
	if dep.ID == "" || dep.Unresolved {
		return nil
	}

	nodeID, name, version := depNodeParts(dep.ID)

	if dep.Circular || seen[nodeID] {
		// Record a pruned leaf so the dep-graph is still complete, but avoid
		// infinite recursion.
		prunedID := nodeID + ":pruned"
		builder.AddNode(prunedID, &depgraph.PkgInfo{Name: name, Version: version},
			depgraph.WithNodeInfo(&depgraph.NodeInfo{
				Labels: map[string]string{"pruned": "true"},
			}),
		)
		if err := builder.ConnectNodes(parentID, prunedID); err != nil {
			return fmt.Errorf("failed to connect pruned node %s -> %s: %w", parentID, prunedID, err)
		}

		return nil
	}

	builder.AddNode(nodeID, &depgraph.PkgInfo{Name: name, Version: version})
	if err := builder.ConnectNodes(parentID, nodeID); err != nil {
		return fmt.Errorf("failed to connect %s -> %s: %w", parentID, nodeID, err)
	}

	seen[nodeID] = true
	for _, child := range dep.Dependencies {
		if err := addDep(builder, child, nodeID, seen); err != nil {
			return err
		}
	}
	// Allow the same package to appear under multiple parents without pruning,
	// but don't re-traverse children we already walked from a different path.
	// Remove from seen so sibling subtrees can include this node without pruning.
	delete(seen, nodeID)

	return nil
}

// depNodeParts splits a GAV-style dependency ID into a stable node ID, name and version.
// For standard "group:artifact:version" IDs the node ID uses "@" as separator
// (consistent with other Snyk dep-graph implementations).
// For non-standard IDs (project references, etc.) the raw string is used.
func depNodeParts(id string) (nodeID, name, version string) {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) == 3 {
		name = parts[0] + ":" + parts[1]
		version = parts[2]
		nodeID = name + "@" + version

		return nodeID, name, version
	}

	return id, id, ""
}

// splitGAV splits "group:artifact:version" into (group:artifact, version).
func splitGAV(gav string) (name, version string) {
	parts := strings.SplitN(gav, ":", 3)
	if len(parts) == 3 {
		return parts[0] + ":" + parts[1], parts[2]
	}

	return gav, ""
}
