package gradle

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

const pkgManagerName = "gradle"

// buildDepGraph converts a single gradleProject into a *depgraph.DepGraph by
// merging the resolved dependencies from all available configurations.
// If options.Gradle.ConfigurationMatching is set, only configurations matching
// the regex pattern will be included.
func buildDepGraph(proj *gradleProject, options *ecosystems.SCAPluginOptions) (*depgraph.DepGraph, error) {
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

	// Create a map of dependency ID to provenance information for quick lookups
	provenanceMap := buildProvenanceMap(proj.Configurations, options)

	// Create function to ensure each edge is added only once across configurations
	connectOnce := createEdgeDeduplicator(builder)

	// Filter configurations based on --configuration-matching if specified
	var configurationMatching string
	if options != nil {
		configurationMatching = options.Gradle.ConfigurationMatching
	}
	configurationsToProcess, err := filterConfigurationsByPattern(proj.Configurations, configurationMatching)
	if err != nil {
		return nil, fmt.Errorf("failed to apply configuration matching pattern '%s': %w", configurationMatching, err)
	}

	// Create context with shared state for dependency graph building
	ctx := &depGraphContext{
		builder:       builder,
		connectOnce:   connectOnce,
		provenanceMap: provenanceMap,
	}

	// Merge all configurations into a single graph.
	// Iterate configurations in Gradle declaration order (preserved by the array
	// format from the init script). The init script processes configurations via
	// project.configurations.matching{...}.each{...}, which iterates in the
	// order configurations were declared. When the same edge appears in multiple
	// configurations, its position in the merged graph is taken from the first
	// configuration that contributes it.
	for _, cfg := range configurationsToProcess {
		if cfg.Error != "" {
			continue
		}
		processed := make(map[string]bool) // Fresh processed set per configuration; tracks components whose subtree we've expanded in this configuration
		for _, dep := range cfg.Root.Dependencies {
			if err := ctx.addDep(&dep, rootNodeID, processed); err != nil {
				return nil, fmt.Errorf("project %s: %w", proj.Path, err)
			}
		}
	}

	return builder.Build(), nil
}

// depGraphContext holds shared state for building a dependency graph from Gradle data.
// This avoids passing multiple parameters through recursive calls.
type depGraphContext struct {
	builder       *depgraph.Builder
	connectOnce   func(parentID, childID string) error
	provenanceMap map[string]*allDepEntry
}

// addDep recursively adds a resolved dependency node and its children to the
// builder.  The Gradle init script (snyk-deps-init.gradle) emits a pre-pruned
// DFS spanning tree of the resolved dependency DAG: each component's children
// appear under exactly one parent per configuration; every subsequent
// reference to the same component is emitted with `pruned: "visited"` or
// `pruned: "cycle"` and no children.  We produce a DAG by handling pruning as:
//
//   - `processed` records every component we've already expanded in this
//     configuration so a malformed input that includes the same expanded
//     subtree twice would still be walked at most once.
//   - Components flagged with `pruned: "cycle"` become labeled `pruned` leaves
//     to maintain the DAG property and avoid infinite recursion.
//   - Components flagged with `pruned: "visited"` (or already in `processed`)
//     are connected to their existing node instead of creating pruned nodes,
//     allowing multiple parents while avoiding infinite recursion.
//   - Components flagged with `constraint: true` (from platform BOMs, dependency
//     locking, or constraints {} blocks) become labeled `constraint` leaves
//     with a `:constraint` node-ID suffix. They do not affect `processed`, so a
//     real edge to the same component will still be expanded normally.
func (ctx *depGraphContext) addDep(dep *gradleDep, parentID string, processed map[string]bool) error {
	if dep.ID == "" {
		return nil
	}

	if dep.Unresolved {
		// ":unresolved" suffix avoids colliding with a resolved node for the same coordinate in another configuration.
		nodeID, name, version := depNodeParts(dep.ID)
		unresolvedID := nodeID + ":unresolved"
		ctx.builder.AddNode(unresolvedID, createPkgInfo(name, version, nil, ctx.provenanceMap != nil),
			depgraph.WithNodeInfo(&depgraph.NodeInfo{
				Labels: map[string]string{"unresolved": "true"},
			}),
		)
		return ctx.connectOnce(parentID, unresolvedID)
	}

	nodeID, name, version := depNodeParts(dep.ID)

	if dep.Constraint {
		// Constraint edges are a separate node so consumers can distinguish
		// version-influencing constraints from real artifact dependencies.
		// Do not mark `processed` — the real edge to this component (if any)
		// must still be expanded fully.
		constraintID := nodeID + ":constraint"
		// Constraints don't get PURLs as they're not real downloadable artifacts
		pkgInfo := &depgraph.PkgInfo{
			Name:    name,
			Version: version,
		}
		ctx.builder.AddNode(constraintID, pkgInfo,
			depgraph.WithNodeInfo(&depgraph.NodeInfo{
				Labels: map[string]string{"constraint": "true"},
			}),
		)
		return ctx.connectOnce(parentID, constraintID)
	}

	if dep.Pruned == pruneCycle {
		// Record a pruned leaf for cycles to maintain DAG property and avoid
		// infinite recursion.
		prunedID := nodeID + ":pruned"
		var provenanceEntry *allDepEntry
		if ctx.provenanceMap != nil {
			provenanceEntry = ctx.provenanceMap[dep.ID]
		}
		pkgInfo := createPkgInfo(name, version, provenanceEntry, ctx.provenanceMap != nil)
		ctx.builder.AddNode(prunedID, pkgInfo,
			depgraph.WithNodeInfo(&depgraph.NodeInfo{
				Labels: map[string]string{"pruned": "true"},
			}),
		)
		return ctx.connectOnce(parentID, prunedID)
	} else if dep.Pruned == pruneVisited || processed[nodeID] {
		// For visited nodes, connect to the existing node instead of creating
		// a pruned version. This produces a DAG where nodes can have multiple
		// parents but no cycles.
		return ctx.connectOnce(parentID, nodeID)
	}

	var provenanceEntry *allDepEntry
	if ctx.provenanceMap != nil {
		provenanceEntry = ctx.provenanceMap[dep.ID]
	}
	pkgInfo := createPkgInfo(name, version, provenanceEntry, ctx.provenanceMap != nil)
	ctx.builder.AddNode(nodeID, pkgInfo)
	if err := ctx.connectOnce(parentID, nodeID); err != nil {
		return err
	}

	processed[nodeID] = true
	for _, child := range dep.Dependencies {
		if err := ctx.addDep(&child, nodeID, processed); err != nil {
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

// filterConfigurationsByPattern filters gradle configurations based on a regex pattern.
// Returns only configurations whose names match the provided regex pattern.
// If pattern is empty, returns all configurations (no filtering).
func filterConfigurationsByPattern(configurations []gradleConfig, pattern string) ([]gradleConfig, error) {
	if pattern == "" {
		return configurations, nil
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	var filtered []gradleConfig
	for _, config := range configurations {
		if regex.MatchString(config.Name) {
			filtered = append(filtered, config)
		}
	}

	return filtered, nil
}

// buildProvenanceMap creates a map from dependency ID to provenance information
// for quick lookups during graph building. When --include-provenance is enabled,
// this allows us to attach checksum and type information to dependencies.
//
// Note: If multiple configurations resolve the same dependency ID to different
// artifacts (different checksums), this takes the first one encountered.
// This could potentially be improved to handle per-configuration artifacts.
func buildProvenanceMap(configurations []gradleConfig, options *ecosystems.SCAPluginOptions) map[string]*allDepEntry {
	if options == nil || !options.Global.IncludeProvenance {
		return nil
	}

	provenanceMap := make(map[string]*allDepEntry)
	for _, cfg := range configurations {
		for i := range cfg.AllDependencies {
			entry := &cfg.AllDependencies[i]
			if entry.Checksum != "" {
				// Only store if we haven't seen this dependency ID before
				// This preserves the "first configuration wins" behavior
				if _, exists := provenanceMap[entry.ID]; !exists {
					provenanceMap[entry.ID] = entry
				}
			}
		}
	}
	return provenanceMap
}

// createEdgeDeduplicator creates a function that ensures each edge is only
// added once to the dependency graph, even when the same edge appears in
// multiple configurations.
func createEdgeDeduplicator(builder *depgraph.Builder) func(parentID, childID string) error {
	// edges tracks (parent → set of children) across the entire merged graph
	// so that an edge contributed by more than one configuration is added to
	// the dep-graph builder exactly once. The dep-graph schema treats Deps as
	// a set of edges, but depgraph.Builder.ConnectNodes is not idempotent —
	// without this guard, a dep present in N configurations would appear as
	// N parallel edges from the same parent.
	edges := make(map[string]map[string]bool)

	return func(parentID, childID string) error {
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
}

// createPkgInfo creates a PkgInfo for standard Gradle dependencies.
// If provenance is enabled and data is available, PURL with checksum information is included.
func createPkgInfo(name, version string, provenanceEntry *allDepEntry, provenanceEnabled bool) *depgraph.PkgInfo {
	pkgInfo := &depgraph.PkgInfo{
		Name:    name,
		Version: version,
	}

	// Only generate PURL when provenance is enabled
	if provenanceEnabled {
		// Generate PURL for standard group:artifact dependencies
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			group := parts[0]
			artifact := parts[1]

			// Build qualifiers for checksum if provenance data is available
			var qualifiers packageurl.Qualifiers
			if provenanceEntry != nil && provenanceEntry.Checksum != "" {
				qualifiers = packageurl.Qualifiers{
					{Key: "checksum", Value: "sha1:" + provenanceEntry.Checksum},
				}
			}

			// Create PURL using pkg:maven for standard Maven coordinates
			// Note: This assumes all dependencies use Maven coordinate format (group:artifact:version).
			// If we later need to surface actual Gradle plugins from the Plugin Portal,
			// we would need to detect and use pkg:gradle for those instead.
			purl := packageurl.NewPackageURL(packageurl.TypeMaven, group, artifact, version, qualifiers, "")
			pkgInfo.PackageURL = purl.ToString()
		}
	}

	return pkgInfo
}
