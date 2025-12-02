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
			tmpDir := createFiles(t, tt.files...)

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
			gotDirs := mockClient.CalledDirs
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
	tmpDir := createFiles(t, "uv.lock")

	mockClient := &mocks.MockUVClient{ReturnErr: errors.New("export failed")}
	plugin := NewUvPlugin(mockClient)

	ctx := context.Background()
	options := &scaplugin.Options{AllProjects: false}
	findings, err := plugin.BuildFindingsFromDir(ctx, tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	require.NotNil(t, findings[0].Error)
	require.ErrorContains(t, findings[0].Error, "failed to build dependency graph")

	require.Equal(t, "uv.lock", findings[0].NormalisedTargetFile)
	require.Empty(t, findings[0].Sbom)
}

func TestPlugin_BuildFindingsFromDir_MixedSuccessAndFailure(t *testing.T) {
	// Create multiple lock files
	tmpDir := createFiles(t,
		"uv.lock",
		"project1/uv.lock",
		"project2/uv.lock",
	)

	// Setup mock to fail for project1 but succeed for others
	mockClient := &mocks.MockUVClient{
		ErrorDirs: map[string]error{
			"project1": errors.New("uv export failed"),
		},
	}
	plugin := NewUvPlugin(mockClient)

	ctx := context.Background()
	options := &scaplugin.Options{AllProjects: true}
	findings, err := plugin.BuildFindingsFromDir(ctx, tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 3)

	// Count successful vs error findings
	successCount := 0
	errorCount := 0
	var errorFinding *scaplugin.Finding
	for i := range findings {
		if findings[i].Error != nil {
			errorCount++
			errorFinding = &findings[i]
		} else {
			successCount++
		}
	}
	require.Equal(t, 2, successCount, "Expected 2 successful findings")
	require.Equal(t, 1, errorCount, "Expected 1 error finding")

	require.NotNil(t, errorFinding)
	require.ErrorContains(t, errorFinding.Error, "failed to build dependency graph")
	require.Equal(t, "project1/uv.lock", errorFinding.NormalisedTargetFile)
	require.Empty(t, errorFinding.Sbom)
}

// Helper to create files.
func createFiles(t *testing.T, files ...string) string {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "uv-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	for _, file := range files {
		fullPath := filepath.Join(tmpDir, file)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte("# test file"), 0o600); err != nil {
			t.Fatalf("Failed to create file %s: %v", fullPath, err)
		}
	}

	return tmpDir
}
