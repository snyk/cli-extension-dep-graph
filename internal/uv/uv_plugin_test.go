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
		exclude      []string // directory/file names to exclude
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
				"node_modules/uv.lock",
				".build/uv.lock",
			},
			allProjects:  true,
			expectedDirs: []string{".", "src"}, // only root and src
		},

		// CLI exclude flag
		{
			name: "excludes directories by name with exclude flag",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
				"src/dir1/uv.lock",
				"src/dir2/uv.lock",
			},
			allProjects:  true,
			exclude:      []string{"dir1"},
			expectedDirs: []string{".", "src/dir2"},
		},
		{
			name: "excludes multiple directories with exclude flag",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
				"dir2/uv.lock",
				"src/uv.lock",
				"src/dir1/uv.lock",
			},
			allProjects:  true,
			exclude:      []string{"dir1", "dir2"},
			expectedDirs: []string{".", "src"},
		},
		{
			name: "exclude flag combined with common excludes",
			files: []string{
				"uv.lock",
				"node_modules/uv.lock",
				"custom-exclude/uv.lock",
				"src/uv.lock",
			},
			allProjects:  true,
			exclude:      []string{"custom-exclude"},
			expectedDirs: []string{".", "src"},
		},
		{
			name: "exclude flag has no effect when allProjects is false",
			files: []string{
				"uv.lock",
				"dir1/uv.lock",
			},
			allProjects:  false,
			exclude:      []string{"dir1"},
			expectedDirs: []string{"."},
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
			options := &scaplugin.Options{AllProjects: tt.allProjects, Exclude: tt.exclude}
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

func TestPlugin_ShouldNotSkipProcessingWhenNoTargetFileIsSet(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &mocks.MockUVClient{}
	plugin := NewUvPlugin(mockClient)

	options := &scaplugin.Options{}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
}

func TestPlugin_ShouldNotSkipProcessingWhenUvLockFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &mocks.MockUVClient{}
	plugin := NewUvPlugin(mockClient)

	options := &scaplugin.Options{TargetFile: "uv.lock"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
}

func TestPlugin_SkipsProcessingWhenTargetFileIsNotUVFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &mocks.MockUVClient{}
	plugin := NewUvPlugin(mockClient)

	options := &scaplugin.Options{TargetFile: "package.json"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_SkipsProcessingWhenTargetFileIsAPyProjectTomlFile(t *testing.T) {
	tmpDir := createFiles(t, "uv.lock", "pyproject.toml", "package.json")

	mockClient := &mocks.MockUVClient{}
	plugin := NewUvPlugin(mockClient)

	options := &scaplugin.Options{TargetFile: "pyproject.toml"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_ShouldNotSkipProcessingWhenTargetFileIsRelativeFolderPath(t *testing.T) {
	tmpDir := createFiles(t,
		"my-project/uv.lock",
		"my-project/pyproject.toml",
		"other-project/uv.lock",
		"other-project/pyproject.toml",
	)

	mockClient := &mocks.MockUVClient{}
	plugin := NewUvPlugin(mockClient)

	options := &scaplugin.Options{TargetFile: "my-project/uv.lock"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 1, "Should return findings for the specific uv.lock file")
	require.NotEmpty(t, mockClient.CalledDirs, "Should have called the uv client")
	require.Equal(t, "my-project", mockClient.CalledDirs[0], "Should have called uv client with the correct directory")
}

func TestPlugin_ShouldSkipProcessingWhenTargetFileIsNotUvLockInRelativeFolderPath(t *testing.T) {
	tmpDir := createFiles(t,
		"my-project/package.json",
		"my-project/package-lock.json",
		"other-project/uv.lock",
		"other-project/pyproject.toml",
	)

	mockClient := &mocks.MockUVClient{}
	plugin := NewUvPlugin(mockClient)

	options := &scaplugin.Options{TargetFile: "my-project/package.json"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)
	require.NoError(t, err)

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
}

func TestPlugin_ShouldRaiseErrorWhenTargetFileIsUvLockInRelativeFolderButDoesNotExist(t *testing.T) {
	tmpDir := createFiles(t,
		"my-project/package.json",
		"my-project/package-lock.json",
		"other-project/uv.lock",
		"other-project/pyproject.toml",
	)

	mockClient := &mocks.MockUVClient{}
	plugin := NewUvPlugin(mockClient)

	options := &scaplugin.Options{TargetFile: "my-project/uv.lock"}
	findings, err := plugin.BuildFindingsFromDir(t.Context(), tmpDir, options, &logger)

	require.Error(t, err)
	require.ErrorContains(t, err, "failed to find uv lockfiles")

	require.Len(t, findings, 0, "Should return no findings")
	require.Empty(t, mockClient.CalledDirs, "Should not call the uv client")
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
