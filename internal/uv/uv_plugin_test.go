package uv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
	"github.com/stretchr/testify/require"
)

var logger = zerolog.Nop()

func TestPlugin_BuildFindingsFromDir(t *testing.T) {
	tests := []struct {
		name         string
		files        []string // files to create relative to root
		allProjects  bool
		expectedDirs []string // expected directories (relative paths) that should be processed
		expectedErr  string   // if non-empty, expect error containing this string
	}{
		// Happy path - single file
		{
			name:         "single uv.lock at root",
			files:        []string{"uv.lock"},
			allProjects:  false,
			expectedDirs: []string{"."},
		},

		// AllProjects behavior
		{
			name:         "AllProjects false - only finds root",
			files:        []string{"uv.lock", "nested/uv.lock"},
			allProjects:  false,
			expectedDirs: []string{"."},
		},
		{
			name:         "AllProjects true - finds all nested files",
			files:        []string{"uv.lock", "project1/uv.lock", "project2/uv.lock", "project1/sub/uv.lock"},
			allProjects:  true,
			expectedDirs: []string{".", "project1", "project1/sub", "project2"},
		},

		// Exclusions
		{
			name: "excludes common folders",
			files: []string{
				"uv.lock",
				"src/uv.lock",
				"node_modules/pkg/uv.lock",
				"venv/uv.lock",
				".git/uv.lock",
				"__pycache__/uv.lock",
				"dist/uv.lock",
				"build/uv.lock",
			},
			allProjects:  true,
			expectedDirs: []string{".", "src"}, // only root and src
		},

		// Edge cases
		{
			name:         "no files found",
			files:        []string{"README.md", "pyproject.toml"},
			allProjects:  true,
			expectedDirs: []string{}, // empty result, no error
		},
		{
			name:         "empty directory",
			files:        []string{},
			allProjects:  true,
			expectedDirs: []string{},
		},
		{
			name:        "missing root file with AllProjects false",
			files:       []string{"README.md"},
			allProjects: false,
			expectedErr: "failed to find uv lockfiles",
		},

		// Multiple projects
		{
			name:         "multiple top-level projects",
			files:        []string{"uv.lock", "backend/uv.lock", "frontend/uv.lock"},
			allProjects:  true,
			expectedDirs: []string{".", "backend", "frontend"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup temp directory
			tmpDir, err := os.MkdirTemp("", "uv-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			// Create test files
			createFiles(t, tmpDir, tt.files)

			// Setup mockClient and plugin
			mockClient := &mocks.MockUVClient{}
			plugin := NewUvPlugin(mockClient)

			// Execute
			ctx := context.Background()
			options := &scaplugin.Options{AllProjects: tt.allProjects}
			findings, err := plugin.BuildFindingsFromDir(ctx, tmpDir, options, &logger)

			// Check error
			if tt.expectedErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}

			// Verify correct directories were processed
			gotDirs := toRelativePaths(t, tmpDir, mockClient.CalledDirs)
			expectedDirs := append([]string{}, tt.expectedDirs...)
			sort.Strings(gotDirs)
			sort.Strings(expectedDirs)

			if len(gotDirs) != len(expectedDirs) {
				t.Errorf("Expected %d directories, got %d\n  expected: %v\n  got:  %v",
					len(expectedDirs), len(gotDirs), expectedDirs, gotDirs)
				return
			}

			for i := range expectedDirs {
				if gotDirs[i] != expectedDirs[i] {
					t.Errorf("Directory mismatch at index %d:\n  expected: %v\n  got:  %v",
						i, expectedDirs, gotDirs)
					break
				}
			}

			if len(findings) != len(tt.expectedDirs) {
				t.Errorf("Expected %d findings, got %d", len(tt.expectedDirs), len(findings))
			}
		})
	}
}

func TestPlugin_BuildFindingsFromDir_ErrorHandling(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uv-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	createFiles(t, tmpDir, []string{"uv.lock"})

	mockClient := &mocks.MockUVClient{ReturnErr: errors.New("export failed")}
	plugin := NewUvPlugin(mockClient)

	ctx := context.Background()
	options := &scaplugin.Options{AllProjects: false}
	_, err = plugin.BuildFindingsFromDir(ctx, tmpDir, options, &logger)

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to export SBOM")
}

// Helper to create files.
func createFiles(t *testing.T, rootDir string, files []string) {
	t.Helper()
	for _, file := range files {
		fullPath := filepath.Join(rootDir, file)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte("# test file"), 0o600); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}
	}
}

// Helper to convert absolute paths to relative paths for comparison.
func toRelativePaths(t *testing.T, rootDir string, absPaths []string) []string {
	t.Helper()
	result := make([]string, len(absPaths))
	for i, absPath := range absPaths {
		relPath, err := filepath.Rel(rootDir, absPath)
		if err != nil {
			t.Fatalf("Failed to get relative path: %v", err)
		}
		result[i] = relPath
	}
	return result
}
