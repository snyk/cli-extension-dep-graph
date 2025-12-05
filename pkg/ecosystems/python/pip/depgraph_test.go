//go:build !integration
// +build !integration

package pip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReport_ToDependencyGraph(t *testing.T) {
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

		dg, err := report.ToDependencyGraph()
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

		dg, err := report.ToDependencyGraph()
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

		dg, err := report.ToDependencyGraph()
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Only root package should be present
		assert.Len(t, dg.Pkgs, 1)
		assert.Equal(t, "pip", dg.PkgManager.Name)
	})

	t.Run("nil report", func(t *testing.T) {
		var report *Report
		_, err := report.ToDependencyGraph()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
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
