package uv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeTargetFile(t *testing.T) {
	tests := []struct {
		name           string
		inputDir       string
		targetFile     string
		expectedResult string
		expectError    bool
	}{
		{
			name:           "empty target file returns empty",
			inputDir:       "/some/dir",
			targetFile:     "",
			expectedResult: "",
			expectError:    false,
		},
		{
			name:           "relative path returns unchanged",
			inputDir:       "/some/dir",
			targetFile:     "subdir/uv.lock",
			expectedResult: "subdir/uv.lock",
			expectError:    false,
		},
		{
			name:           "simple filename returns unchanged",
			inputDir:       "/some/dir",
			targetFile:     "uv.lock",
			expectedResult: "uv.lock",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := normaliseTargetFile(tt.inputDir, tt.targetFile)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestNormalizeTargetFile_WithRealPaths(t *testing.T) {
	// Create temp directory with actual files for testing absolute paths
	tmpDir := createFiles(t, "uv.lock", "nested/uv.lock")

	// Resolve symlinks in tmpDir for accurate comparison
	resolvedTmpDir, err := filepath.EvalSymlinks(tmpDir)
	require.NoError(t, err)

	t.Run("absolute path at root returns filename", func(t *testing.T) {
		absolutePath := filepath.Join(resolvedTmpDir, "uv.lock")
		result, err := normaliseTargetFile(tmpDir, absolutePath)
		require.NoError(t, err)
		require.Equal(t, "uv.lock", result)
	})

	t.Run("absolute path in subdirectory returns relative path", func(t *testing.T) {
		absolutePath := filepath.Join(resolvedTmpDir, "nested", "uv.lock")
		result, err := normaliseTargetFile(tmpDir, absolutePath)
		require.NoError(t, err)
		require.Equal(t, "nested/uv.lock", result)
	})

	t.Run("absolute path with symlinked inputDir resolves correctly", func(t *testing.T) {
		// Create a symlink to the temp directory
		symlinkDir, err := os.MkdirTemp("", "symlink-test-*")
		require.NoError(t, err)
		t.Cleanup(func() { os.RemoveAll(symlinkDir) })

		symlinkPath := filepath.Join(symlinkDir, "link")
		err = os.Symlink(resolvedTmpDir, symlinkPath)
		require.NoError(t, err)

		// Use absolute path through symlink for target, original dir for inputDir
		absolutePath := filepath.Join(symlinkPath, "uv.lock")
		result, err := normaliseTargetFile(tmpDir, absolutePath)
		require.NoError(t, err)
		require.Equal(t, "uv.lock", result)
	})

	t.Run("non-existent absolute path returns error", func(t *testing.T) {
		absolutePath := filepath.Join(resolvedTmpDir, "nonexistent", "uv.lock")
		_, err := normaliseTargetFile(tmpDir, absolutePath)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve target file path")
	})
}
