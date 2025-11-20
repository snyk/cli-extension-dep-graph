package pip

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// depStringPattern extracts the package name from a dependency string.
// Example: "urllib3 (<3,>=1.21.1)" -> "urllib3".
// Example: "certifi (>=2017.4.17)" -> "certifi".
// Example: "idna (<4,>=2.5)" -> "idna".
var depStringPattern = regexp.MustCompile(`^([a-zA-Z0-9._-]+)`)

// ToDepgraph converts a pip install Report into a Depgraph.
// The root package ID is "root" and points to all direct dependencies.
func (r *Report) ToDepgraph() (*ecosystems.Depgraph, error) {
	if r == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	slog.Info("Converting pip report to depgraph", slog.Int("total_packages", len(r.Install)))

	// First pass: index packages by name for dependency resolution
	// Pip's dependency resolver ensures only one version of each package is installed
	slog.Debug("Building package name index for dependency resolution")
	packageByName := make(map[string]InstallItem)
	for _, item := range r.Install {
		packageByName[strings.ToLower(item.Metadata.Name)] = item
	}

	// Second pass: build packages, graph, and collect direct dependencies
	slog.Debug("Building dependency graph")
	packages := make(map[ecosystems.PackageID]ecosystems.Package)
	graph := make(map[ecosystems.PackageID][]ecosystems.PackageID)
	var directDeps []ecosystems.PackageID

	for _, item := range r.Install {
		version := item.Metadata.Version
		if version == "" {
			slog.Debug("Package has empty version, using fallback",
				slog.String("package", item.Metadata.Name))
			version = "?"
		}
		pkgID := toPackageID(item.Metadata.Name, version)

		// Add to packages map
		packages[pkgID] = ecosystems.Package{
			PackageID:   pkgID,
			PackageName: item.Metadata.Name,
			Version:     version,
		}

		// Track direct dependencies
		if item.IsDirectDependency() {
			directDeps = append(directDeps, pkgID)
		}

		// Build dependency list for this package
		var deps []ecosystems.PackageID
		for _, depString := range item.Metadata.RequiresDist {
			if depName := extractPackageName(depString); depName != "" {
				if depItem, found := packageByName[strings.ToLower(depName)]; found {
					depVersion := depItem.Metadata.Version
					if depVersion == "" {
						depVersion = "?"
					}
					deps = append(deps, toPackageID(depItem.Metadata.Name, depVersion))
				}
			}
		}
		graph[pkgID] = deps
	}

	// Add root pointing to direct dependencies
	graph["root"] = directDeps

	slog.Info("Successfully converted pip report to depgraph",
		slog.Int("total_packages", len(packages)),
		slog.Int("direct_dependencies", len(directDeps)),
		slog.Int("graph_nodes", len(graph)))

	return &ecosystems.Depgraph{
		Packages:      packages,
		Graph:         graph,
		RootPackageID: "root",
	}, nil
}

// toPackageID creates a PackageID in the format "name@version".
func toPackageID(name, version string) ecosystems.PackageID {
	return ecosystems.PackageID(fmt.Sprintf("%s@%s", name, version))
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
