package uv_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/uv"
)

func TestHasLockFile(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("does not find uv.lock file when all-projects is false and uv.lock exists in subfolder", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createLockFile(t, tmpDir, "project1")

		result := uv.HasLockFile(tmpDir, "", false, &nopLogger)
		assert.False(t, result)
	})

	t.Run("finds uv.lock file when all-projects is true and uv.lock exists in subfolder", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createLockFile(t, tmpDir, "project1")

		result := uv.HasLockFile(tmpDir, "", true, &nopLogger)
		assert.True(t, result)
	})
}

func TestHasLockFileSingle(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when uv.lock exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createLockFile(t, tmpDir)

		result := uv.HasLockFileSingle(tmpDir, "", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createLockFile(t, tmpDir)

		result := uv.HasLockFileSingle(tmpDir, "uv.lock", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file in subdirectory", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createLockFile(t, tmpDir, "subdir")

		result := uv.HasLockFileSingle(tmpDir, "subdir/uv.lock", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with absolute target path", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createLockFile(t, tmpDir, "subdir")
		absolutePath := filepath.Join(tmpDir, "subdir", uv.LockFileName)

		result := uv.HasLockFileSingle(tmpDir, absolutePath, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when uv.lock does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		result := uv.HasLockFileSingle(dir, "", &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when directory does not exist", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nonexistent")

		result := uv.HasLockFileSingle(dir, "", &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when target file is not uv.lock even if it exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		otherFile := filepath.Join(tmpDir, "pom.xml")
		err := os.WriteFile(otherFile, []byte("<project></project>"), 0o600)
		require.NoError(t, err)

		result := uv.HasLockFileSingle(tmpDir, "pom.xml", &nopLogger)
		assert.False(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createLockFile(t, dir)

		result := uv.HasLockFileSingle(dir, "", nil)
		assert.True(t, result)
	})
}

func TestHasLockFileRecursive(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when uv.lock exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createLockFile(t, tmpDir)

		result := uv.HasLockFileRecursive(tmpDir, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists in subdirectory", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		createLockFile(t, tmpDir, "subdir")

		result := uv.HasLockFileRecursive(tmpDir, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when uv.lock exists in excluded subdirectory", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		createLockFile(t, tmpDir, "node_modules")
		createLockFile(t, tmpDir, "subdir", "node_modules")
		createLockFile(t, tmpDir, ".build")

		result := uv.HasLockFileRecursive(tmpDir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when uv.lock does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		result := uv.HasLockFileRecursive(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when directory does not exist", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nonexistent")

		result := uv.HasLockFileRecursive(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		createLockFile(t, dir)

		result := uv.HasLockFileRecursive(dir, nil)
		assert.True(t, result)
	})
}

func createLockFile(t *testing.T, rootDir string, subFolders ...string) {
	t.Helper()

	lockDir := filepath.Join(append([]string{rootDir}, subFolders...)...)
	err := os.MkdirAll(lockDir, 0o755)
	require.NoError(t, err)

	lockPath := filepath.Join(lockDir, uv.LockFileName)
	err = os.WriteFile(lockPath, []byte("# test"), 0o600)
	require.NoError(t, err)
}
