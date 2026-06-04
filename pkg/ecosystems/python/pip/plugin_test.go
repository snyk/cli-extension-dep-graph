//go:build !integration
// +build !integration

package pip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

func ptr(s string) *string { return &s }

func TestGetProjectName(t *testing.T) {
	tests := map[string]struct {
		filePath string
		scanDir  string
		override *string
		expected string
	}{
		"override_takes_precedence": {
			filePath: "project/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: ptr("custom-name"),
			expected: "custom-name",
		},
		"empty_override_is_ignored": {
			filePath: "project/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: ptr(""),
			expected: "project",
		},
		"nil_override_uses_directory": {
			filePath: "project/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: nil,
			expected: "project",
		},
		"nested_path_uses_immediate_parent": {
			filePath: "project/test/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: nil,
			expected: "test",
		},
		"root_file_falls_back_to_scan_dir": {
			filePath: "requirements.txt",
			scanDir:  "/path/to/myproject",
			override: nil,
			expected: "myproject",
		},
		"deeply_nested_uses_immediate_parent": {
			filePath: "a/b/c/d/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: nil,
			expected: "d",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := GetProjectName(tt.filePath, tt.scanDir, tt.override)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPlugin_DiscoverRequirementsFiles_HonorsExcludePaths locks in that the pip plugin
// reads `opts.Global.ExcludePaths` (the channel the orchestrator and SBOM-resolution
// paths use to propagate processed files and the user's `--exclude-paths` flag) and
// passes those paths through to the discovery layer's exclude filter.
func TestPlugin_DiscoverRequirementsFiles_HonorsExcludePaths(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{"requirements.txt", "a/requirements.txt", "b/requirements.txt"} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o644))
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/requirements.txt"})

	got, err := Plugin{}.discoverRequirementsFiles(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.NotContains(t, rels, "a/requirements.txt",
		"discovery must skip the path supplied via opts.Global.ExcludePaths")
	assert.Contains(t, rels, "requirements.txt")
	assert.Contains(t, rels, "b/requirements.txt")
}
