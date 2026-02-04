//go:build !integration
// +build !integration

package pip

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

func TestReport_ToDependencyGraph(t *testing.T) {
	t.Run("normalizes package names to match pipenv key field", func(t *testing.T) {
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:    "BeautifulSoup4", // Mixed case in pip metadata
						Version: "4.12.2",
						RequiresDist: []string{
							"soupsieve>1.2",
						},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:    "Jinja2", // Mixed case in pip metadata
						Version: "3.1.2",
						RequiresDist: []string{
							"MarkupSafe>=2.0",
						},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "mypy_extensions", // Underscore in pip metadata
						Version:      "1.0.0",
						RequiresDist: []string{},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "zc.lockfile", // Dot in pip metadata
						Version:      "3.0.0",
						RequiresDist: []string{},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "soupsieve",
						Version:      "2.5",
						RequiresDist: []string{},
					},
					Requested: false,
				},
				{
					Metadata: PackageMetadata{
						Name:         "MarkupSafe",
						Version:      "2.1.3",
						RequiresDist: []string{},
					},
					Requested: false,
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Verify names are normalized in packages (lowercase + _ and . replaced with -)
		pkgByName := make(map[string]string) // name -> version
		for _, pkg := range dg.Pkgs {
			pkgByName[pkg.Info.Name] = pkg.Info.Version
		}
		assert.Equal(t, "4.12.2", pkgByName["beautifulsoup4"], "BeautifulSoup4 should be normalized")
		assert.Equal(t, "3.1.2", pkgByName["jinja2"], "Jinja2 should be normalized")
		assert.Equal(t, "1.0.0", pkgByName["mypy-extensions"], "mypy_extensions should have _ replaced with -")
		assert.Equal(t, "3.0.0", pkgByName["zc.lockfile"], "zc.lockfile maintains .")
		assert.Equal(t, "2.5", pkgByName["soupsieve"])
		assert.Equal(t, "2.1.3", pkgByName["markupsafe"], "MarkupSafe should be normalized")

		// Verify names are normalized in nodeIDs
		nodeByID := make(map[string]bool)
		for _, node := range dg.Graph.Nodes {
			nodeByID[node.NodeID] = true
		}
		assert.True(t, nodeByID["beautifulsoup4@4.12.2"], "BeautifulSoup4 nodeID should be normalized")
		assert.True(t, nodeByID["jinja2@3.1.2"], "Jinja2 nodeID should be normalized")
		assert.True(t, nodeByID["mypy-extensions@1.0.0"], "mypy_extensions nodeID should have _ replaced with -")
		assert.True(t, nodeByID["zc.lockfile@3.0.0"], "zc.lockfile nodeID should maintain .")
		assert.True(t, nodeByID["soupsieve@2.5"])
		assert.True(t, nodeByID["markupsafe@2.1.3"], "MarkupSafe nodeID should be normalized")
	})

	t.Run("simple report with direct and transitive deps", func(t *testing.T) {
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:    "requests",
						Version: "2.31.0",
						RequiresDist: []string{
							"urllib3 (<3,>=1.21.1)",
							"certifi (>=2017.4.17)",
						},
					},
					Requested: true, // Direct dependency
				},
				{
					Metadata: PackageMetadata{
						Name:    "urllib3",
						Version: "2.0.4",
						RequiresDist: []string{
							"certifi",
						},
					},
					Requested: false, // Transitive dependency
				},
				{
					Metadata: PackageMetadata{
						Name:         "certifi",
						Version:      "2023.7.22",
						RequiresDist: []string{}, // Leaf package
					},
					Requested: false, // Transitive dependency
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Verify package manager
		assert.Equal(t, "pip", dg.PkgManager.Name)

		// Verify packages are present
		assert.Len(t, dg.Pkgs, 4) // 3 packages + root package

		// Find packages by name
		pkgNames := make(map[string]bool)
		for _, pkg := range dg.Pkgs {
			pkgNames[pkg.Info.Name] = true
		}
		assert.True(t, pkgNames["requests"])
		assert.True(t, pkgNames["urllib3"])
		assert.True(t, pkgNames["certifi"])

		// Verify graph has nodes
		assert.NotNil(t, dg.Graph)
		assert.NotEmpty(t, dg.Graph.RootNodeID)
	})

	t.Run("multiple direct dependencies", func(t *testing.T) {
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:         "requests",
						Version:      "2.31.0",
						RequiresDist: []string{},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "flask",
						Version:      "2.3.0",
						RequiresDist: []string{},
					},
					Requested: true,
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Verify packages (2 deps + 1 root)
		assert.Len(t, dg.Pkgs, 3)

		// Verify package manager
		assert.Equal(t, "pip", dg.PkgManager.Name)
	})

	t.Run("empty report", func(t *testing.T) {
		report := &Report{
			Install: []InstallItem{},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Only root package should be present
		assert.Len(t, dg.Pkgs, 1)
		assert.Equal(t, "pip", dg.PkgManager.Name)
	})

	t.Run("nil report", func(t *testing.T) {
		var report *Report
		_, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("includes extra deps when requested_extras is set", func(t *testing.T) {
		// arrow[test] was requested, so pytest should be connected as arrow's dep
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:    "arrow",
						Version: "1.3.0",
						RequiresDist: []string{
							"python-dateutil>=2.7.0",
							`pytest; extra == "test"`,
							`pytest-cov; extra == "test"`,
							`sphinx; extra == "docs"`,
						},
					},
					Requested:       true,
					RequestedExtras: []string{"test"}, // arrow[test] was requested
				},
				{
					Metadata: PackageMetadata{
						Name:         "python-dateutil",
						Version:      "2.8.2",
						RequiresDist: []string{},
					},
					Requested: false,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pytest",
						Version:      "7.4.3",
						RequiresDist: []string{},
					},
					Requested: false, // Installed because of arrow[test]
				},
				{
					Metadata: PackageMetadata{
						Name:         "pytest-cov",
						Version:      "4.1.0",
						RequiresDist: []string{},
					},
					Requested: false,
				},
				{
					Metadata: PackageMetadata{
						Name:         "sphinx",
						Version:      "7.0.0",
						RequiresDist: []string{},
					},
					Requested: false,
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Find arrow's node and check its deps
		var arrowDeps []string
		for _, node := range dg.Graph.Nodes {
			if node.NodeID == "arrow@1.3.0" {
				for _, dep := range node.Deps {
					arrowDeps = append(arrowDeps, dep.NodeID)
				}
				break
			}
		}

		// arrow should have: python-dateutil, pytest, pytest-cov (test extras)
		// but NOT sphinx (docs extra was not requested)
		assert.Contains(t, arrowDeps, "python-dateutil@2.8.2", "should have python-dateutil")
		assert.Contains(t, arrowDeps, "pytest@7.4.3", "should have pytest")
		assert.Contains(t, arrowDeps, "pytest-cov@4.1.0", "should have pytest-cov")

		// sphinx should NOT be connected as arrow's dep
		for _, dep := range arrowDeps {
			assert.NotContains(t, dep, "sphinx")
		}
	})

	t.Run("filters extra deps when requested_extras is empty", func(t *testing.T) {
		// arrow was requested without extras, so pytest should NOT be connected
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:    "arrow",
						Version: "1.3.0",
						RequiresDist: []string{
							"python-dateutil>=2.7.0",
							`pytest; extra == "test"`,
						},
					},
					Requested:       true,
					RequestedExtras: nil, // No extras requested
				},
				{
					Metadata: PackageMetadata{
						Name:         "python-dateutil",
						Version:      "2.8.2",
						RequiresDist: []string{},
					},
					Requested: false,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pytest",
						Version:      "7.4.3",
						RequiresDist: []string{},
					},
					Requested: true, // pytest is in requirements.txt directly
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Find arrow's node and check its deps
		var arrowDeps []string
		for _, node := range dg.Graph.Nodes {
			if node.NodeID == "arrow@1.3.0" {
				for _, dep := range node.Deps {
					arrowDeps = append(arrowDeps, dep.NodeID)
				}
				break
			}
		}

		// arrow should only have python-dateutil, NOT pytest
		assert.Contains(t, arrowDeps, "python-dateutil@2.8.2", "should have python-dateutil")
		assert.NotContains(t, arrowDeps, "pytest@7.4.3", "should NOT have pytest")
	})
}

func TestToDependencyGraph_PruningBehavior(t *testing.T) {
	// Test that pruning matches pip-deps behavior:
	// - Each top-level dep gets its own fresh visited set
	// - Siblings within a subtree share the same visited set
	// - A node is pruned if it was already visited by an earlier sibling's subtree
	t.Run("prunes duplicate within same top-level subtree", func(t *testing.T) {
		// A depends on C and D, C also depends on D
		// D should appear under C, but be pruned when appearing as A's direct dep
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:         "pkg-a",
						Version:      "1.0.0",
						RequiresDist: []string{"pkg-c", "pkg-d"},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pkg-c",
						Version:      "1.0.0",
						RequiresDist: []string{"pkg-d"},
					},
					Requested: false,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pkg-d",
						Version:      "1.0.0",
						RequiresDist: []string{},
					},
					Requested: false,
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)

		// Find pkg-a's deps
		var pkgADeps []string
		for _, node := range dg.Graph.Nodes {
			if node.NodeID == "pkg-a@1.0.0" {
				for _, dep := range node.Deps {
					pkgADeps = append(pkgADeps, dep.NodeID)
				}
				break
			}
		}

		// pkg-a should have pkg-c and pkg-d:pruned (D was visited via C first)
		assert.Contains(t, pkgADeps, "pkg-c@1.0.0", "pkg-a should have pkg-c")
		// The second instance of pkg-d (reached directly from pkg-a) should be pruned
		hasPrunedD := false
		for _, dep := range pkgADeps {
			if strings.HasPrefix(dep, "pkg-d@1.0.0:pruned") {
				// Check if this node is marked as pruned
				for _, node := range dg.Graph.Nodes {
					if node.NodeID == dep && node.Info != nil && node.Info.Labels["pruned"] == "true" {
						hasPrunedD = true
						break
					}
				}
			}
		}
		assert.True(t, hasPrunedD, "pkg-d should be pruned since it was visited via pkg-c first")
	})

	t.Run("does not prune across different top-level subtrees", func(t *testing.T) {
		// A and B are both top-level, both depend on C
		// C should appear under both (same node, multiple edges)
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:         "pkg-a",
						Version:      "1.0.0",
						RequiresDist: []string{"pkg-c"},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pkg-b",
						Version:      "1.0.0",
						RequiresDist: []string{"pkg-c"},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pkg-c",
						Version:      "1.0.0",
						RequiresDist: []string{},
					},
					Requested: false,
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)

		// Find pkg-a and pkg-b deps
		var pkgADeps, pkgBDeps []string
		for _, node := range dg.Graph.Nodes {
			if node.NodeID == "pkg-a@1.0.0" {
				for _, dep := range node.Deps {
					pkgADeps = append(pkgADeps, dep.NodeID)
				}
			}
			if node.NodeID == "pkg-b@1.0.0" {
				for _, dep := range node.Deps {
					pkgBDeps = append(pkgBDeps, dep.NodeID)
				}
			}
		}

		// Both should have pkg-c (same node, multiple edges pointing to it)
		assert.Contains(t, pkgADeps, "pkg-c@1.0.0", "pkg-a should have pkg-c")
		assert.Contains(t, pkgBDeps, "pkg-c@1.0.0", "pkg-b should also have pkg-c")
	})

	t.Run("no duplicate child deps when node reached from multiple parents", func(t *testing.T) {
		// A and B both depend on C, and C depends on D
		// D should only appear once as a child of C, not duplicated
		report := &Report{
			Install: []InstallItem{
				{
					Metadata: PackageMetadata{
						Name:         "pkg-a",
						Version:      "1.0.0",
						RequiresDist: []string{"pkg-c"},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pkg-b",
						Version:      "1.0.0",
						RequiresDist: []string{"pkg-c"},
					},
					Requested: true,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pkg-c",
						Version:      "1.0.0",
						RequiresDist: []string{"pkg-d"},
					},
					Requested: false,
				},
				{
					Metadata: PackageMetadata{
						Name:         "pkg-d",
						Version:      "1.0.0",
						RequiresDist: []string{},
					},
					Requested: false,
				},
			},
		}

		dg, err := report.ToDependencyGraph(context.Background(), logger.Nop(), "pip")
		require.NoError(t, err)

		// Find pkg-c's deps - should only have ONE pkg-d, not duplicated
		var pkgCDeps []string
		for _, node := range dg.Graph.Nodes {
			if node.NodeID == "pkg-c@1.0.0" {
				for _, dep := range node.Deps {
					pkgCDeps = append(pkgCDeps, dep.NodeID)
				}
				break
			}
		}

		// pkg-c should have exactly one pkg-d dependency
		assert.Equal(t, 1, len(pkgCDeps), "pkg-c should have exactly 1 dep, got: %v", pkgCDeps)
		assert.Contains(t, pkgCDeps, "pkg-d@1.0.0", "pkg-c should have pkg-d")
	})
}

func TestExtractPackageName(t *testing.T) {
	tests := map[string]struct {
		depString string
		want      string
	}{
		"with_constraints":        {"urllib3 (<3,>=1.21.1)", "urllib3"},
		"with_extras":             {"requests[security] (>=2.20.0)", "requests"},
		"special_chars":           {"some-package_name.py (>=1.0)", "some-package_name.py"},
		"no_constraints":          {"certifi", "certifi"},
		"empty":                   {"", ""},
		"no_space_version":        {"idna>=3.3", "idna"},
		"with_extra_marker":       {"mypy; extra == \"dev\"", "mypy"},
		"hyphenated_with_extra":   {"pre-commit; extra == \"dev\"", "pre-commit"},
		"hyphenated_with_marker":  {"pytest-cov; extra == \"dev\"", "pytest-cov"},
		"multiple_hyphens":        {"pytest-socket; extra == \"dev\"", "pytest-socket"},
		"simple_with_extra":       {"pytest; extra == \"dev\"", "pytest"},
		"single_char_with_marker": {"ruff; extra == \"dev\"", "ruff"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractPackageName(tt.depString))
		})
	}
}

func TestExtractDepNamesWithExtras(t *testing.T) {
	tests := map[string]struct {
		requiresDist    []string
		requestedExtras []string
		want            []string
		notWant         []string
	}{
		"includes extras when requested": {
			requiresDist: []string{
				"python-dateutil>=2.7.0",
				`pytest; extra == "test"`,
				`pytest-cov; extra == "test"`,
				`sphinx; extra == "docs"`,
			},
			requestedExtras: []string{"test"},
			want:            []string{"python-dateutil", "pytest", "pytest-cov"},
			notWant:         []string{"sphinx"},
		},
		"includes multiple extras when requested": {
			requiresDist: []string{
				"numpy>=1.20",
				`pytest; extra == "test"`,
				`sphinx; extra == "docs"`,
				`black; extra == "dev"`,
			},
			requestedExtras: []string{"test", "docs"},
			want:            []string{"numpy", "pytest", "sphinx"},
			notWant:         []string{"black"},
		},
		"filters all extras when requestedExtras is nil": {
			requiresDist: []string{
				"numpy>=1.20",
				`pytest; extra == "test"`,
			},
			requestedExtras: nil,
			want:            []string{"numpy"},
			notWant:         []string{"pytest"},
		},
		"case insensitive extra matching": {
			requiresDist: []string{
				`pytest; extra == "TEST"`,
				`sphinx; extra == "Docs"`,
			},
			requestedExtras: []string{"test", "docs"},
			want:            []string{"pytest", "sphinx"},
		},
		"deduplicates same package with different markers": {
			requiresDist: []string{
				"six>=1.5",
				`six; python_version < "3"`,
				`six>=1.10; python_version >= "3"`,
			},
			requestedExtras: nil,
			want:            []string{"six"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			names := extractDepNamesWithExtras(tt.requiresDist, tt.requestedExtras)

			assert.Len(t, names, len(tt.want))
			for _, w := range tt.want {
				assert.Contains(t, names, w)
			}
			for _, nw := range tt.notWant {
				assert.NotContains(t, names, nw)
			}
		})
	}
}

func TestExtractExtraName(t *testing.T) {
	tests := map[string]struct {
		depString string
		want      string
	}{
		"double_quotes":   {`pytest; extra == "test"`, "test"},
		"single_quotes":   {`pytest; extra == 'dev'`, "dev"},
		"no_spaces":       {`pytest; extra=="test"`, "test"},
		"extra_spaces":    {`pytest ;  extra  ==  "docs"`, "docs"},
		"with_version":    {`pytest (>=7.0) ; extra == "test"`, "test"},
		"no_extra":        {"numpy>=1.20", ""},
		"platform_marker": {`pywin32; sys_platform == "win32"`, ""},
		"empty":           {"", ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractExtraName(tt.depString))
		})
	}
}
