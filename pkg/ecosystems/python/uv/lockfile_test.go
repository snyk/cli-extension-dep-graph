package uv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasUvLockFile(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("does not find uv.lock file when all-projects flag is set to false and uv.lock file exists in subfolder", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "project1")

		result := HasUvLockFile(tmpDir, "", false, &nopLogger)
		assert.False(t, result)
	})

	t.Run("does find uv.lock file when all-projects flag is set to true and uv.lock file exists in subfolder", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "project1")

		result := HasUvLockFile(tmpDir, "", true, &nopLogger)
		assert.True(t, result)
	})
}

func TestHasUvLockFileSingle(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when uv.lock exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir)

		result := hasUvLockFileSingle(tmpDir, "", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir)

		result := hasUvLockFileSingle(tmpDir, "uv.lock", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file in subdirectory", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "subdir")

		result := hasUvLockFileSingle(tmpDir, "subdir/uv.lock", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file in subdirectory and giving absolute path", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "subdir")
		absolutePath := filepath.Join(tmpDir, "subdir", LockFileName)

		result := hasUvLockFileSingle(tmpDir, absolutePath, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when uv.lock does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		result := hasUvLockFileSingle(dir, "", &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when directory does not exist", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nonexistent")

		result := hasUvLockFileSingle(dir, "", &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when target file is not uv.lock even if it exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		otherFile := filepath.Join(tmpDir, "pom.xml")
		err := os.WriteFile(otherFile, []byte("<project></project>"), 0o600)
		require.NoError(t, err)

		result := hasUvLockFileSingle(tmpDir, "pom.xml", &nopLogger)
		assert.False(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createUvLockFile(t, dir)

		result := hasUvLockFileSingle(dir, "", nil)
		assert.True(t, result)
	})
}

func TestHasUvLockFileRecursive(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when uv.lock exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir)

		result := hasUvLockFileRecursive(tmpDir, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists in subdirectory", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "subdir")

		result := hasUvLockFileRecursive(tmpDir, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when uv.lock exists in excluded subdirectory", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "node_modules")
		createUvLockFile(t, tmpDir, "subdir", "node_modules")
		createUvLockFile(t, tmpDir, ".build")

		result := hasUvLockFileRecursive(tmpDir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when uv.lock does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		result := hasUvLockFileRecursive(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when directory does not exist", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nonexistent")

		result := hasUvLockFileRecursive(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createUvLockFile(t, dir)

		result := hasUvLockFileRecursive(dir, nil)
		assert.True(t, result)
	})
}

func TestHasUvLockFileInAnyDir(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when first directory has uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()
		createUvLockFile(t, dir1)

		result := HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when second directory has uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()
		createUvLockFile(t, dir2)

		result := HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when multiple directories have uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()
		createUvLockFile(t, dir1)
		createUvLockFile(t, dir2)

		result := HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when no directories have uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		result := HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false for empty directory list", func(t *testing.T) {
		t.Parallel()

		result := HasUvLockFileInAnyDir([]string{}, "", false, &nopLogger)
		assert.False(t, result)
	})

	t.Run("handles mix of existing and non-existing directories", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		nonExistentDir := filepath.Join(t.TempDir(), "nonexistent")
		createUvLockFile(t, dir1)

		result := HasUvLockFileInAnyDir([]string{nonExistentDir, dir1}, "", false, &nopLogger)
		assert.True(t, result)
	})
}

func createUvLockFile(t *testing.T, rootDir string, subFolders ...string) {
	t.Helper()

	uvLockDir := filepath.Join(append([]string{rootDir}, subFolders...)...)
	err := os.MkdirAll(uvLockDir, 0o755)
	require.NoError(t, err)

	uvLockPath := filepath.Join(uvLockDir, LockFileName)
	err = os.WriteFile(uvLockPath, []byte("# test"), 0o600)
	require.NoError(t, err)
}
