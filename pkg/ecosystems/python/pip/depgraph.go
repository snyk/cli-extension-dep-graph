package pip

import (
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

// depStringPattern extracts the package name from a dependency string.
// Example: "urllib3 (<3,>=1.21.1)" -> "urllib3".
// Example: "certifi (>=2017.4.17)" -> "certifi".
// Example: "idna (<4,>=2.5)" -> "idna".
var depStringPattern = regexp.MustCompile(`^([a-zA-Z0-9._-]+)`)

func normalizePackageName(name string) string {
	normalized := strings.ToLower(name)
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, ".", "-")
	return normalized
}

// packageInfo holds pre-computed package information to avoid redundant calculations.
type packageInfo struct {
	normalizedName string
	version        string
	nodeID         string
	item           *InstallItem
}

// ToDependencyGraph converts a pip install Report into a DepGraph using the dep-graph builder.
// The root node represents the project and points to all direct dependencies.
func (r *Report) ToDependencyGraph() (*depgraph.DepGraph, error) {
	if r == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	numPackages := len(r.Install)
	slog.Debug("Converting pip report to dependency graph", slog.Int("total_packages", numPackages))

	// Create a builder with pip as the package manager and a root package
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: "pip"},
		&depgraph.PkgInfo{Name: "root", Version: "0.0.0"},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create depgraph builder: %w", err)
	}

	// Build package index by normalized name
	packageByName := make(map[string]*packageInfo, numPackages)
	for i := range r.Install {
		item := &r.Install[i]

		normalizedName := normalizePackageName(item.Metadata.Name)
		version := item.Metadata.Version
		if version == "" {
			slog.Debug("Package has empty version, using fallback",
				slog.String("package", item.Metadata.Name))
			version = "?"
		}
		nodeID := normalizedName + "@" + version

		packageByName[normalizedName] = &packageInfo{
			normalizedName: normalizedName,
			version:        version,
			nodeID:         nodeID,
			item:           item,
		}
	}

	// Collect direct dependencies
	var directDeps []*packageInfo
	for _, info := range packageByName {
		if info.item.IsDirectDependency() {
			directDeps = append(directDeps, info)
		}
	}

	// Create virtual root package info for DFS starting point
	rootPkg := &packageInfo{
		normalizedName: "root",
		version:        "0.0.0",
		nodeID:         builder.GetRootNode().NodeID,
		item: &InstallItem{
			Metadata: PackageMetadata{
				Name:    "root",
				Version: "0.0.0",
			},
		},
	}

	// Build dependency list for root (direct dependencies)
	rootDeps := make([]string, 0, len(directDeps))
	for _, dep := range directDeps {
		rootDeps = append(rootDeps, dep.normalizedName)
	}
	// Sort for deterministic traversal order
	sort.Strings(rootDeps)

	// DFS traversal with pruning
	visited := make(map[string]bool)
	if err := dfsVisit(builder, packageByName, rootPkg, rootDeps, visited); err != nil {
		return nil, err
	}

	slog.Debug("Successfully converted pip report to dependency graph",
		slog.Int("total_packages", numPackages),
		slog.Int("direct_dependencies", len(directDeps)))

	return builder.Build(), nil
}

// dfsVisit performs depth-first traversal to build the dependency graph.
// It tracks visited nodes and creates pruned nodes for cycles/repeated dependencies.
func dfsVisit(
	builder *depgraph.Builder,
	packageByName map[string]*packageInfo,
	pkg *packageInfo,
	depNames []string,
	visited map[string]bool,
) error {
	parentID := pkg.nodeID

	for _, depName := range depNames {
		depInfo, found := packageByName[normalizePackageName(depName)]
		if !found {
			continue
		}

		childID := depInfo.nodeID

		// Check if already visited - create pruned node if so
		if visited[childID] {
			prunedID := childID + ":pruned"
			prunedNode := builder.AddNode(prunedID, &depgraph.PkgInfo{
				Name:    depInfo.normalizedName,
				Version: depInfo.version,
			})
			// Set pruned label to match pip-deps behavior
			prunedNode.Info = &depgraph.NodeInfo{
				Labels: map[string]string{"pruned": "true"},
			}

			if err := builder.ConnectNodes(parentID, prunedID); err != nil {
				return fmt.Errorf("failed to connect pruned dependency %s -> %s: %w", parentID, prunedID, err)
			}
			continue
		}

		// Add node and connect to parent
		builder.AddNode(childID, &depgraph.PkgInfo{
			Name:    depInfo.normalizedName,
			Version: depInfo.version,
		})

		if err := builder.ConnectNodes(parentID, childID); err != nil {
			return fmt.Errorf("failed to connect dependency %s -> %s: %w", parentID, childID, err)
		}

		// Mark as visited and recurse
		visited[childID] = true

		// Get dependencies for this package (sorted for deterministic order)
		childDepNames := extractDepNames(depInfo.item.Metadata.RequiresDist)
		sort.Strings(childDepNames)
		if err := dfsVisit(builder, packageByName, depInfo, childDepNames, visited); err != nil {
			return err
		}
	}

	return nil
}

// extractDepNames extracts package names from a list of dependency strings.
func extractDepNames(requiresDist []string) []string {
	names := make([]string, 0, len(requiresDist))
	for _, depString := range requiresDist {
		if name := extractPackageName(depString); name != "" {
			names = append(names, name)
		}
	}
	return names
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
