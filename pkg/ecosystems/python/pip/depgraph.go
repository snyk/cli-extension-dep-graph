package pip

import (
	"fmt"
	"log/slog"
	"regexp"
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

	// Pre-allocate with known capacity
	packageByName := make(map[string]*packageInfo, numPackages)
	directDepNodeIDs := make([]string, 0, numPackages/2) // Estimate ~50% are direct

	// First pass: build index, add nodes, and collect direct deps
	for i := range r.Install {
		item := &r.Install[i]

		normalizedName := normalizePackageName(item.Metadata.Name)
		version := item.Metadata.Version
		if version == "" {
			slog.Debug("Package has empty version, using fallback",
				slog.String("package", item.Metadata.Name))
			version = "?"
		}
		nodeID := normalizedName + "@" + version // Faster than fmt.Sprintf

		// Cache computed values
		info := &packageInfo{
			normalizedName: normalizedName,
			version:        version,
			nodeID:         nodeID,
			item:           item,
		}
		packageByName[normalizedName] = info

		// Add node to builder
		builder.AddNode(nodeID, &depgraph.PkgInfo{
			Name:    normalizedName,
			Version: version,
		})

		// Track direct dependencies
		if item.IsDirectDependency() {
			directDepNodeIDs = append(directDepNodeIDs, nodeID)
		}
	}

	// Second pass: connect dependencies (must be after all nodes exist)
	for _, info := range packageByName {
		for _, depString := range info.item.Metadata.RequiresDist {
			depName := extractPackageName(depString)
			if depName == "" {
				continue
			}

			depInfo, found := packageByName[normalizePackageName(depName)]
			if !found {
				continue
			}

			if err := builder.ConnectNodes(info.nodeID, depInfo.nodeID); err != nil {
				return nil, fmt.Errorf("failed to connect dependency %s -> %s: %w", info.nodeID, depInfo.nodeID, err)
			}
		}
	}

	// Connect root node to direct dependencies
	rootNodeID := builder.GetRootNode().NodeID
	for _, depNodeID := range directDepNodeIDs {
		if err := builder.ConnectNodes(rootNodeID, depNodeID); err != nil {
			return nil, fmt.Errorf("failed to connect root to dependency %s: %w", depNodeID, err)
		}
	}

	slog.Debug("Successfully converted pip report to dependency graph",
		slog.Int("total_packages", numPackages),
		slog.Int("direct_dependencies", len(directDepNodeIDs)))

	return builder.Build(), nil
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
