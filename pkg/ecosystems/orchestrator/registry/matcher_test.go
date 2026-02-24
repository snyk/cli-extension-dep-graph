package registry

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// mockPlugin is a test implementation of SCAPlugin
type mockPlugin struct {
	name       string
	capability ecosystems.PluginCapability
}

func (m *mockPlugin) Name() string {
	return m.name
}

func (m *mockPlugin) Capability() ecosystems.PluginCapability {
	return m.capability
}

func (m *mockPlugin) BuildDepGraphsFromDir(ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions) ([]ecosystems.SCAResult, error) {
	return nil, nil
}

func TestFindBestPluginForFile(t *testing.T) {
	tests := []struct {
		name           string
		plugins        []ecosystems.SCAPlugin
		fileName       string
		availableFiles map[string]discovery.FindResult
		companionFiles []string // Files to create on disk for companion checks
		expectedPlugin string
		expectedNil    bool
	}{
		{
			name: "single plugin matches",
			plugins: []ecosystems.SCAPlugin{
				&mockPlugin{
					name: "pip",
					capability: ecosystems.PluginCapability{
						PrimaryManifests:   []string{"requirements.txt"},
						RequiredCompanions: []string{},
					},
				},
			},
			fileName:       "requirements.txt",
			availableFiles: map[string]discovery.FindResult{},
			expectedPlugin: "pip",
			expectedNil:    false,
		},
		{
			name: "no plugin matches",
			plugins: []ecosystems.SCAPlugin{
				&mockPlugin{
					name: "pip",
					capability: ecosystems.PluginCapability{
						PrimaryManifests:   []string{"requirements.txt"},
						RequiredCompanions: []string{},
					},
				},
			},
			fileName:       "package.json",
			availableFiles: map[string]discovery.FindResult{},
			expectedPlugin: "",
			expectedNil:    true,
		},
		{
			name: "plugin with required companion missing",
			plugins: []ecosystems.SCAPlugin{
				&mockPlugin{
					name: "poetry",
					capability: ecosystems.PluginCapability{
						PrimaryManifests:   []string{"pyproject.toml"},
						RequiredCompanions: []string{"poetry.lock"},
					},
				},
			},
			fileName:       "pyproject.toml",
			availableFiles: map[string]discovery.FindResult{},
			companionFiles: []string{}, // No poetry.lock
			expectedPlugin: "",
			expectedNil:    true,
		},
		{
			name: "most specific plugin wins",
			plugins: []ecosystems.SCAPlugin{
				&mockPlugin{
					name: "pip",
					capability: ecosystems.PluginCapability{
						PrimaryManifests:   []string{"requirements.txt"},
						RequiredCompanions: []string{},
					},
				},
				&mockPlugin{
					name: "uv",
					capability: ecosystems.PluginCapability{
						PrimaryManifests:   []string{"requirements.txt"},
						RequiredCompanions: []string{"uv.lock"},
					},
				},
			},
			fileName:       "requirements.txt",
			availableFiles: map[string]discovery.FindResult{},
			companionFiles: []string{"uv.lock"}, // uv.lock exists
			expectedPlugin: "uv",                // uv is more specific
			expectedNil:    false,
		},
		{
			name: "generic plugin when specific requirements not met",
			plugins: []ecosystems.SCAPlugin{
				&mockPlugin{
					name: "pip",
					capability: ecosystems.PluginCapability{
						PrimaryManifests:   []string{"requirements.txt"},
						RequiredCompanions: []string{},
					},
				},
				&mockPlugin{
					name: "uv",
					capability: ecosystems.PluginCapability{
						PrimaryManifests:   []string{"requirements.txt"},
						RequiredCompanions: []string{"uv.lock"},
					},
				},
			},
			fileName:       "requirements.txt",
			availableFiles: map[string]discovery.FindResult{},
			companionFiles: []string{}, // No uv.lock
			expectedPlugin: "pip",      // Falls back to pip
			expectedNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directory for this test
			tmpDir := t.TempDir()

			// Create companion files if specified
			for _, file := range tt.companionFiles {
				filePath := filepath.Join(tmpDir, file)
				if err := os.WriteFile(filePath, []byte(""), 0644); err != nil {
					t.Fatalf("failed to create companion file %s: %v", file, err)
				}
			}

			result := findBestPluginForFile(tt.plugins, tt.fileName, tmpDir, tt.availableFiles)

			if tt.expectedNil {
				if result != nil {
					t.Errorf("expected nil, got plugin %s", result.Name())
				}
			} else {
				if result == nil {
					t.Errorf("expected plugin %s, got nil", tt.expectedPlugin)
				} else if result.Name() != tt.expectedPlugin {
					t.Errorf("expected plugin %s, got %s", tt.expectedPlugin, result.Name())
				}
			}
		})
	}
}

func TestGroupFilesByDirectory(t *testing.T) {
	files := []discovery.FindResult{
		{Path: "/root/requirements.txt", RelPath: "requirements.txt"},
		{Path: "/root/subdir1/requirements.txt", RelPath: "subdir1/requirements.txt"},
		{Path: "/root/subdir1/Pipfile", RelPath: "subdir1/Pipfile"},
		{Path: "/root/subdir2/requirements.txt", RelPath: "subdir2/requirements.txt"},
	}

	result := groupFilesByDirectory(files)

	expectedDirs := map[string]int{
		"/root":         1,
		"/root/subdir1": 2,
		"/root/subdir2": 1,
	}

	if len(result) != len(expectedDirs) {
		t.Errorf("expected %d directories, got %d", len(expectedDirs), len(result))
	}

	for dir, expectedCount := range expectedDirs {
		files, exists := result[dir]
		if !exists {
			t.Errorf("expected directory %s not found", dir)
			continue
		}
		if len(files) != expectedCount {
			t.Errorf("directory %s: expected %d files, got %d", dir, expectedCount, len(files))
		}
	}
}

func TestMatchPluginsInDirectory(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	// Create test files
	requirementsPath := filepath.Join(tmpDir, "requirements.txt")
	pipfilePath := filepath.Join(tmpDir, "Pipfile")
	pipfileLockPath := filepath.Join(tmpDir, "Pipfile.lock")

	if err := os.WriteFile(requirementsPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pipfilePath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pipfileLockPath, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	plugins := []ecosystems.SCAPlugin{
		&mockPlugin{
			name: "pip",
			capability: ecosystems.PluginCapability{
				PrimaryManifests:   []string{"requirements.txt"},
				RequiredCompanions: []string{},
			},
		},
		&mockPlugin{
			name: "pipenv",
			capability: ecosystems.PluginCapability{
				PrimaryManifests:   []string{"Pipfile"},
				RequiredCompanions: []string{"Pipfile.lock"},
			},
		},
	}

	files := []discovery.FindResult{
		{Path: requirementsPath, RelPath: "requirements.txt"},
		{Path: pipfilePath, RelPath: "Pipfile"},
		{Path: pipfileLockPath, RelPath: "Pipfile.lock"},
	}

	matches := matchPluginsInDirectory(plugins, tmpDir, files)

	// Should match both pip and pipenv
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}

	// Verify we got both plugins
	pluginNames := make(map[string]bool)
	for _, match := range matches {
		pluginNames[match.Plugin.Name()] = true
	}

	if !pluginNames["pip"] {
		t.Error("expected pip plugin match")
	}
	if !pluginNames["pipenv"] {
		t.Error("expected pipenv plugin match")
	}
}
