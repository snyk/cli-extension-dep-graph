//go:build !integration

package gradle

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── ResolveGradleBinary ──────────────────────────────────────────────────────

func TestResolveGradleBinary(t *testing.T) {
	t.Run("returns system gradle when no wrapper present", func(t *testing.T) {
		dir := t.TempDir()
		binary, err := ResolveGradleBinary(dir, false)
		require.NoError(t, err)
		// Should resolve to actual gradle binary path via exec.LookPath
		assert.Contains(t, binary, "gradle")
	})

	t.Run("prefers gradlew when present and executable", func(t *testing.T) {
		dir := t.TempDir()
		wrapperPath := filepath.Join(dir, "gradlew")
		require.NoError(t, os.WriteFile(wrapperPath, []byte("#!/bin/sh"), 0o755))

		binary, err := ResolveGradleBinary(dir, false)
		require.NoError(t, err)
		assert.Equal(t, wrapperPath, binary)
	})

	t.Run("falls back to gradle when gradlew is not executable", func(t *testing.T) {
		dir := t.TempDir()
		wrapperPath := filepath.Join(dir, "gradlew")
		require.NoError(t, os.WriteFile(wrapperPath, []byte("#!/bin/sh"), 0o644)) // not executable

		binary, err := ResolveGradleBinary(dir, false)
		require.NoError(t, err)
		assert.Contains(t, binary, "gradle")
	})

	t.Run("uses platform-appropriate wrapper when present", func(t *testing.T) {
		dir := t.TempDir()
		gradlewPath := filepath.Join(dir, "gradlew")
		gradlewBatPath := filepath.Join(dir, "gradlew.bat")

		require.NoError(t, os.WriteFile(gradlewPath, []byte("#!/bin/sh"), 0o755))
		require.NoError(t, os.WriteFile(gradlewBatPath, []byte("@echo off"), 0o755))

		binary, err := ResolveGradleBinary(dir, false)
		require.NoError(t, err)

		if runtime.GOOS == "windows" {
			assert.Equal(t, gradlewBatPath, binary)
		} else {
			assert.Equal(t, gradlewPath, binary)
		}
	})

	t.Run("skip wrapper flag bypasses wrapper discovery", func(t *testing.T) {
		dir := t.TempDir()
		wrapperPath := filepath.Join(dir, "gradlew")
		require.NoError(t, os.WriteFile(wrapperPath, []byte("#!/bin/sh"), 0o755))

		// Even though wrapper exists, should skip it when flag is true
		binary, err := ResolveGradleBinary(dir, true)
		require.NoError(t, err)
		assert.Contains(t, binary, "gradle")
		assert.NotEqual(t, wrapperPath, binary)
	})

	t.Run("finds wrapper in parent directory", func(t *testing.T) {
		parentDir := t.TempDir()
		childDir := filepath.Join(parentDir, "subproject")
		require.NoError(t, os.MkdirAll(childDir, 0o755))

		// Create wrapper in parent directory
		var wrapperName string
		if runtime.GOOS == "windows" {
			wrapperName = "gradlew.bat"
		} else {
			wrapperName = "gradlew"
		}
		wrapperPath := filepath.Join(parentDir, wrapperName)
		require.NoError(t, os.WriteFile(wrapperPath, []byte("#!/bin/sh"), 0o755))

		// Should find wrapper by walking up from childDir (project directory)
		binary, err := ResolveGradleBinary(childDir, false)
		require.NoError(t, err)

		// Use filepath.Base comparison to avoid symlink path differences on macOS
		assert.Equal(t, wrapperName, filepath.Base(binary))
		assert.Contains(t, binary, parentDir)
	})

	t.Run("returns error when gradle not found and no wrapper", func(t *testing.T) {
		// This test would need to mock exec.LookPath to simulate gradle not being available
		// For now, we'll skip this as it requires more complex mocking setup
		t.Skip("Requires mocking exec.LookPath to simulate gradle not found")
	})
}
