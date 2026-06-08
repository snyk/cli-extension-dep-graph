//go:build !integration
// +build !integration

package poetry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeManifest(t *testing.T, dir, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, PyprojectTomlFileName), []byte(body), 0o600))
}

func TestReadPyproject_V1(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `[tool.poetry]
name = "demo-v1"
version = "1.2.3"
`)
	m, err := readPyproject(dir)
	require.NoError(t, err)
	assert.Equal(t, "demo-v1", m.Tool.Poetry.Name)
	assert.Equal(t, "1.2.3", m.Tool.Poetry.Version)
	assert.Empty(t, m.Project.Name)
}

func TestReadPyproject_V2(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `[project]
name = "demo-v2"
version = "9.8.7"
`)
	m, err := readPyproject(dir)
	require.NoError(t, err)
	assert.Equal(t, "demo-v2", m.Project.Name)
	assert.Equal(t, "9.8.7", m.Project.Version)
}

func TestResolveRootPkg_PrecedenceMatrix(t *testing.T) {
	override := "from-cli"

	tests := map[string]struct {
		manifest    *pyprojectTOML
		scanDir     string
		override    *string
		wantName    string
		wantVersion string
	}{
		"override_beats_everything": {
			manifest: &pyprojectTOML{
				Project: struct {
					Name    string `toml:"name"`
					Version string `toml:"version"`
				}{Name: "manifest-name", Version: "5.0.0"},
			},
			scanDir:     "/scan/somepkg",
			override:    &override,
			wantName:    "from-cli",
			wantVersion: "5.0.0", // override doesn't supply a version, so manifest wins
		},
		"v2_project_table_wins_over_tool_poetry": {
			manifest: &pyprojectTOML{
				Project: struct {
					Name    string `toml:"name"`
					Version string `toml:"version"`
				}{Name: "v2-name", Version: "2.0.0"},
				Tool: struct {
					Poetry struct {
						Name        string `toml:"name"`
						Version     string `toml:"version"`
						PackageMode *bool  `toml:"package-mode"`
					} `toml:"poetry"`
				}{
					Poetry: struct {
						Name        string `toml:"name"`
						Version     string `toml:"version"`
						PackageMode *bool  `toml:"package-mode"`
					}{Name: "v1-name", Version: "1.0.0"},
				},
			},
			scanDir:     "/scan/somepkg",
			wantName:    "v2-name",
			wantVersion: "2.0.0",
		},
		"falls_back_to_tool_poetry": {
			manifest: &pyprojectTOML{
				Tool: struct {
					Poetry struct {
						Name        string `toml:"name"`
						Version     string `toml:"version"`
						PackageMode *bool  `toml:"package-mode"`
					} `toml:"poetry"`
				}{
					Poetry: struct {
						Name        string `toml:"name"`
						Version     string `toml:"version"`
						PackageMode *bool  `toml:"package-mode"`
					}{Name: "v1-name", Version: "1.0.0"},
				},
			},
			scanDir:     "/scan/somepkg",
			wantName:    "v1-name",
			wantVersion: "1.0.0",
		},
		"falls_back_to_scan_dir_basename": {
			manifest:    &pyprojectTOML{},
			scanDir:     "/scan/somepkg",
			wantName:    "somepkg",
			wantVersion: DefaultRootVersion,
		},
		"final_fallback_when_dirname_is_dot": {
			manifest:    nil,
			scanDir:     ".",
			wantName:    DefaultRootName,
			wantVersion: DefaultRootVersion,
		},
		"empty_override_is_treated_as_unset": {
			manifest: &pyprojectTOML{
				Project: struct {
					Name    string `toml:"name"`
					Version string `toml:"version"`
				}{Name: "manifest-name", Version: "1.0.0"},
			},
			scanDir:     "/scan",
			override:    func() *string { s := ""; return &s }(),
			wantName:    "manifest-name",
			wantVersion: "1.0.0",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := resolveRootPkg(tt.manifest, tt.scanDir, tt.override)
			assert.Equal(t, tt.wantName, got.Name)
			assert.Equal(t, tt.wantVersion, got.Version)
		})
	}
}
