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

	// edges tracks (parent → set of children) across the entire merged graph
	// so that an edge contributed by more than one configuration is added to
	// the dep-graph builder exactly once. The dep-graph schema treats Deps as
	// a set of edges, but depgraph.Builder.ConnectNodes is not idempotent —
	// without this guard, a dep present in N configurations would appear as
	// N parallel edges from the same parent.
	edges := make(map[string]map[string]bool)
	connectOnce := func(parentID, childID string) error {
		children := edges[parentID]
		if children == nil {
			children = make(map[string]bool)
			edges[parentID] = children
		}
		if children[childID] {
			return nil
		}
		children[childID] = true
		if err := builder.ConnectNodes(parentID, childID); err != nil {
			return fmt.Errorf("failed to connect %s -> %s: %w", parentID, childID, err)
		}
		return nil
	}

	// Merge all configurations into a single graph.  Per-configuration
	// filtering (e.g. --configuration-matching, preferring runtimeClasspath)
	// will be added when feature parity work begins.
	//
	// Iterate configurations in Gradle declaration order (preserved by the array
	// format from the init script). The init script processes configurations via
	// project.configurations.matching{...}.each{...}, which iterates in the
	// order configurations were declared. When the same edge appears in multiple
	// configurations, its position in the merged graph is taken from the first
	// configuration that contributes it.
	for _, cfg := range proj.Configurations {
		if cfg.Error != "" {
			continue
		}
		processed := make(map[string]bool) // Fresh processed set per configuration; tracks components whose subtree we've expanded in this configuration
		for _, dep := range cfg.Root.Dependencies {
			if err := addDep(builder, &dep, rootNodeID, processed, connectOnce); err != nil {
				return nil, fmt.Errorf("project %s: %w", proj.Path, err)
			}
		}
	}

	return builder.Build(), nil
}

// addDep recursively adds a resolved dependency node and its children to the
// builder.  The Gradle init script (snyk-deps-init.gradle) emits a pre-pruned
// DFS spanning tree of the resolved dependency DAG: each component's children
// appear under exactly one parent per configuration; every subsequent
// reference to the same component is emitted with `pruned: "visited"` or
// `pruned: "cycle"` and no children.  We mirror that shape here:
//
//   - `processed` records every component we've already expanded in this
//     configuration so a malformed input that includes the same expanded
//     subtree twice would still be walked at most once.
//   - Components flagged with any `pruned` value by the init script (or already in
//     `processed`) become labeled `pruned` leaves so the tree shape matches
//     `gradle dependencies` text output and downstream "vulnerable path"
//     counts remain meaningful.
//
// connectOnce wraps depgraph.Builder.ConnectNodes with deduplication so that
// the same (parent, child) edge is only added once across the entire merged
// graph (configurations are merged into one dep-graph per project).
func addDep(builder *depgraph.Builder, dep *gradleDep, parentID string, processed map[string]bool, connectOnce func(parentID, childID string) error) error {
	if dep.ID == "" || dep.Unresolved {
		return nil
	}

	nodeID, name, version := depNodeParts(dep.ID)

	if dep.Pruned.IsPruned() || processed[nodeID] {
		// Record a pruned leaf so the dep-graph is still complete, but avoid
		// infinite recursion.
		prunedID := nodeID + ":pruned"
		builder.AddNode(prunedID, &depgraph.PkgInfo{Name: name, Version: version},
			depgraph.WithNodeInfo(&depgraph.NodeInfo{
				Labels: map[string]string{"pruned": "true"},
			}),
		)
		return connectOnce(parentID, prunedID)
	}

	builder.AddNode(nodeID, &depgraph.PkgInfo{Name: name, Version: version})
	if err := connectOnce(parentID, nodeID); err != nil {
		return err
	}

	processed[nodeID] = true
	for _, child := range dep.Dependencies {
		if err := addDep(builder, &child, nodeID, processed, connectOnce); err != nil {
			return err
		}
	}

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
