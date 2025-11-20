//go:build !integration
// +build !integration

package pip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

func TestReport_ToDepgraph(t *testing.T) {
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

		depgraph, err := report.ToDepgraph()
		require.NoError(t, err)

		// Verify structure
		assert.Equal(t, ecosystems.PackageID("root"), depgraph.RootPackageID)
		assert.Len(t, depgraph.Packages, 3)
		assert.Len(t, depgraph.Graph, 4) // 3 packages + root

		// Verify root points to direct dependency
		assert.Equal(t, []ecosystems.PackageID{"requests@2.31.0"}, depgraph.Graph["root"])

		// Verify dependency chain
		assert.ElementsMatch(t, []ecosystems.PackageID{"urllib3@2.0.4", "certifi@2023.7.22"},
			depgraph.Graph["requests@2.31.0"])
		assert.Equal(t, []ecosystems.PackageID{"certifi@2023.7.22"},
			depgraph.Graph["urllib3@2.0.4"])
		assert.Empty(t, depgraph.Graph["certifi@2023.7.22"])
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

		depgraph, err := report.ToDepgraph()
		require.NoError(t, err)

		assert.Len(t, depgraph.Packages, 2)
		assert.ElementsMatch(t, []ecosystems.PackageID{"requests@2.31.0", "flask@2.3.0"},
			depgraph.Graph["root"])
	})

	t.Run("empty report", func(t *testing.T) {
		report := &Report{
			Install: []InstallItem{},
		}

		depgraph, err := report.ToDepgraph()
		require.NoError(t, err)

		assert.Empty(t, depgraph.Packages)
		assert.Empty(t, depgraph.Graph["root"])
	})

	t.Run("nil report", func(t *testing.T) {
		var report *Report
		_, err := report.ToDepgraph()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})
}

func TestExtractPackageName(t *testing.T) {
	tests := map[string]struct {
		depString string
		want      string
	}{
		"with_constraints": {"urllib3 (<3,>=1.21.1)", "urllib3"},
		"with_extras":      {"requests[security] (>=2.20.0)", "requests"},
		"special_chars":    {"some-package_name.py (>=1.0)", "some-package_name.py"},
		"no_constraints":   {"certifi", "certifi"},
		"empty":            {"", ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractPackageName(tt.depString))
		})
	}
}

func TestToPackageID(t *testing.T) {
	tests := map[string]struct {
		name    string
		version string
		want    ecosystems.PackageID
	}{
		"standard package": {
			name:    "requests",
			version: "2.31.0",
			want:    "requests@2.31.0",
		},
		"package with dash": {
			name:    "some-package",
			version: "1.0.0",
			want:    "some-package@1.0.0",
		},
		"empty version": {
			name:    "package",
			version: "",
			want:    "package@", // toPackageID doesn't handle fallback
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := toPackageID(tt.name, tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}
