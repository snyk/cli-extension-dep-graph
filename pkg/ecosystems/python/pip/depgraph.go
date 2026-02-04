package pip

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// depStringPattern extracts the package name from a dependency string.
// Example: "urllib3 (<3,>=1.21.1)" -> "urllib3".
// Example: "certifi (>=2017.4.17)" -> "certifi".
// Example: "idna (<4,>=2.5)" -> "idna".
var depStringPattern = regexp.MustCompile(`^([a-zA-Z0-9._-]+)`)

// extraPattern extracts the extra name from a dependency string's marker.
// Example: "pytest ; extra == 'test'" -> "test".
// Example: "sphinx ; extra == \"docs\"" -> "docs".
var extraPattern = regexp.MustCompile(`extra\s*==\s*['"]([^'"]+)['"]`)

func normalizePackageName(name string) string {
	normalized := strings.ToLower(name)
	normalized = strings.ReplaceAll(normalized, "_", "-")
	return normalized
}

// packageLookup provides fast access to packages by normalized name using indices.
type packageLookup struct {
	nameToIndex map[string]int
	install     []InstallItem
}

// findPackage returns the install item for a normalized package name, or nil if not found.
func (pl *packageLookup) findPackage(normalizedName string) *InstallItem {
	if index, exists := pl.nameToIndex[normalizedName]; exists {
		return &pl.install[index]
	}
	return nil
}

// getNodeID generates the node ID for a package without storing it.
func getNodeID(item *InstallItem) string {
	return item.Metadata.GetNormalizePackageName() + "@" + item.Metadata.GetNormalizeVersion()
}

// ToDependencyGraph converts a pip install Report into a DepGraph using the dep-graph builder.
// The root node represents the project and points to all direct dependencies.
// The pkgManager parameter specifies the package manager name (e.g., "pip", "pipenv").
func (r *Report) ToDependencyGraph(ctx context.Context, log logger.Logger, pkgManager string) (*depgraph.DepGraph, error) {
	if r == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	numPackages := len(r.Install)
	log.Debug(ctx, "Converting pip report to dependency graph", logger.Attr("total_packages", numPackages))

	// Create a builder with the specified package manager and a root package
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: pkgManager},
		&depgraph.PkgInfo{Name: "root", Version: "0.0.0"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create depgraph builder: %w", err)
	}

	// Build lightweight package lookup using only indices (no data duplication)
	lookup := &packageLookup{
		nameToIndex: make(map[string]int, numPackages),
		install:     r.Install,
	}
	for i := range r.Install {
		item := &r.Install[i]
		normalizedName := item.Metadata.GetNormalizePackageName()
		lookup.nameToIndex[normalizedName] = i

		if item.Metadata.Version == "" {
			log.Debug(ctx, "Package has empty version, using fallback",
				logger.Attr("package", item.Metadata.Name))
		}
	}

	// Collect direct dependencies (just normalized names, no struct allocation)
	var directDeps []string
	for i := range r.Install {
		item := &r.Install[i]
		if item.IsDirectDependency() {
			normalizedName := item.Metadata.GetNormalizePackageName()
			directDeps = append(directDeps, normalizedName)
		}
	}

	// Sort direct dependencies for deterministic traversal order
	sort.Strings(directDeps)

	// DFS traversal with pruning - process directly from lookup
	// - visited: per-path set for cycle detection (nil = create fresh for each top-level)
	// - processed: tracks nodes whose children have already been added (prevent duplicate edges)
	processed := make(map[string]bool)
	rootNodeID := builder.GetRootNode().NodeID
	if err := dfsVisitDirect(builder, lookup, rootNodeID, directDeps, nil, processed); err != nil {
		return nil, err
	}

	log.Debug(ctx, "Successfully converted pip report to dependency graph",
		logger.Attr("total_packages", numPackages),
		logger.Attr("direct_dependencies", len(directDeps)))

	return builder.Build(), nil
}

// dfsVisitDirect performs depth-first traversal to build the dependency graph using direct lookup.
// Parameters:
//   - visited: per-path set for cycle detection. When nil (root call), each top-level dep gets fresh set.
//   - processed: tracks nodes whose children have already been added (prevents duplicate edges).
func dfsVisitDirect(
	builder *depgraph.Builder,
	lookup *packageLookup,
	parentID string,
	depNames []string,
	visited map[string]bool,
	processed map[string]bool,
) error {
	for _, depName := range depNames {
		normalizedDepName := normalizePackageName(depName)
		depItem := lookup.findPackage(normalizedDepName)
		if depItem == nil {
			continue
		}

		childID := getNodeID(depItem) // e.g., "python-dateutil@2.8.2"

		// Create a new set for each top-level dep, or use the shared set for recursive calls
		localVisited := visited
		if localVisited == nil {
			localVisited = make(map[string]bool)
		}

		// Check if already visited on this path - create pruned node if so (cycle detection)
		if localVisited[childID] {
			// Create pruned node with :pruned suffix (matches TypeScript pipenv-parser)
			prunedNodeID := fmt.Sprintf("%s:pruned", childID)
			normalizedName := depItem.Metadata.GetNormalizePackageName()
			version := depItem.Metadata.GetNormalizeVersion()

			builder.AddNode(prunedNodeID, &depgraph.PkgInfo{
				Name:    normalizedName,
				Version: version,
			}, depgraph.WithNodeInfo(&depgraph.NodeInfo{
				Labels: map[string]string{"pruned": "true"},
			}))

			if err := builder.ConnectNodes(parentID, prunedNodeID); err != nil {
				return fmt.Errorf("failed to connect pruned dependency %s -> %s: %w", parentID, prunedNodeID, err)
			}
			continue
		}

		// Add node and connect to parent
		normalizedName := depItem.Metadata.GetNormalizePackageName()
		version := depItem.Metadata.GetNormalizeVersion()

		builder.AddNode(childID, &depgraph.PkgInfo{
			Name:    normalizedName,
			Version: version,
		})

		if err := builder.ConnectNodes(parentID, childID); err != nil {
			return fmt.Errorf("failed to connect dependency %s -> %s: %w", parentID, childID, err)
		}

		// Add to visited set for cycle detection on this path
		localVisited[childID] = true

		// Only process children if this node hasn't been processed yet
		// This prevents adding duplicate child edges when node is reached from multiple paths
		if !processed[childID] {
			processed[childID] = true

			// Get dependencies for this package (sorted for deterministic order)
			childDepNames := extractDepNamesWithExtras(depItem.Metadata.RequiresDist, depItem.RequestedExtras)
			sort.Strings(childDepNames)
			if err := dfsVisitDirect(builder, lookup, childID, childDepNames, localVisited, processed); err != nil {
				return err
			}
		}
	}

	return nil
}

// extractDepNamesWithExtras extracts unique package names from a list of dependency strings,
// filtering out optional extras unless they match the requestedExtras.
// If requestedExtras is nil or empty, all extras are filtered out.
// Duplicate package names are deduplicated (same package may appear multiple times with different markers).
func extractDepNamesWithExtras(requiresDist, requestedExtras []string) []string {
	seen := make(map[string]bool)
	names := make([]string, 0, len(requiresDist))
	for _, depString := range requiresDist {
		// Check if this is an extra dependency
		extraName := extractExtraName(depString)
		if extraName != "" {
			// It's an extra dependency - only include if the extra was requested
			if !containsExtra(requestedExtras, extraName) {
				continue
			}
		}
		if name := extractPackageName(depString); name != "" {
			// Deduplicate - same package may appear multiple times with different version constraints
			normalizedName := normalizePackageName(name)
			if !seen[normalizedName] {
				seen[normalizedName] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// containsExtra checks if the extra name is in the requested extras slice (case-insensitive).
func containsExtra(requestedExtras []string, extraName string) bool {
	for _, e := range requestedExtras {
		if strings.EqualFold(e, extraName) {
			return true
		}
	}
	return false
}

// extractExtraName extracts the extra name from a dependency string's marker.
// Returns empty string if no extra marker is found.
// Example: "pytest ; extra == 'test'" -> "test".
// Example: "sphinx ; extra == \"docs\"" -> "docs".
func extractExtraName(depString string) string {
	matches := extraPattern.FindStringSubmatch(depString)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractPackageName extracts the package name from a dependency string.
// Example: "urllib3 (<3,>=1.21.1)" -> "urllib3".
func extractPackageName(depString string) string {
	matches := depStringPattern.FindStringSubmatch(depString)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
