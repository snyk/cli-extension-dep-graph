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

// setupFakeGradle creates a fake gradle binary in a temporary directory
// and adds it to PATH for the duration of the test
func setupFakeGradle(t *testing.T) func() {
	t.Helper()

	// Create temporary directory for fake gradle
	tmpDir := t.TempDir()

	// Create fake gradle executable
	gradlePath := filepath.Join(tmpDir, "gradle")
	if runtime.GOOS == "windows" {
		gradlePath += ".exe"
	}

	// Write a simple script/executable
	content := "#!/bin/sh\necho 'fake gradle'\n"
	if runtime.GOOS == "windows" {
		content = "@echo off\necho fake gradle\n"
	}

	require.NoError(t, os.WriteFile(gradlePath, []byte(content), 0o755))

	// Save original PATH and modify it
	originalPath := os.Getenv("PATH")
	separator := ":"
	if runtime.GOOS == "windows" {
		separator = ";"
	}
	newPath := tmpDir + separator + originalPath
	require.NoError(t, os.Setenv("PATH", newPath))

	// Return cleanup function
	return func() {
		os.Setenv("PATH", originalPath)
	}
}

// ── ResolveGradleBinary ──────────────────────────────────────────────────────

func TestResolveGradleBinary(t *testing.T) {
	t.Run("returns system gradle when no wrapper present", func(t *testing.T) {
		cleanup := setupFakeGradle(t)
		defer cleanup()

		dir := t.TempDir()
		binary, err := ResolveGradleBinary(dir, false)
		require.NoError(t, err)
		// Should resolve to actual gradle binary path via exec.LookPath
		assert.Contains(t, binary, "gradle")
	})

	t.Run("prefers gradlew when present and executable", func(t *testing.T) {
		dir := t.TempDir()
		wrapperPath := filepath.Join(dir, "gradlew")
		require.NoError(t, os.WriteFile(wrapperPath, nil, 0o755))

		binary, err := ResolveGradleBinary(dir, false)
		require.NoError(t, err)
		assert.Equal(t, wrapperPath, binary)
	})

	t.Run("falls back to gradle when gradlew is not executable (Unix only)", func(t *testing.T) {
		cleanup := setupFakeGradle(t)
		defer cleanup()

		// Mock Unix OS - Windows doesn't have this scenario
		originalDetector := osDetector
		osDetector = func() string { return "linux" }
		defer func() { osDetector = originalDetector }()

		dir := t.TempDir()
		wrapperPath := filepath.Join(dir, "gradlew")
		require.NoError(t, os.WriteFile(wrapperPath, nil, 0o644)) // not executable

		binary, err := ResolveGradleBinary(dir, false)
		require.NoError(t, err)
		assert.Contains(t, binary, "gradle")
	})

	t.Run("uses platform-appropriate wrapper when present", func(t *testing.T) {
		testCases := []struct {
			name            string
			mockOS          string
			expectedWrapper string
		}{
			{"windows", "windows", "gradlew.bat"},
			{"unix", "linux", "gradlew"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				gradlewPath := filepath.Join(dir, "gradlew")
				gradlewBatPath := filepath.Join(dir, "gradlew.bat")

				require.NoError(t, os.WriteFile(gradlewPath, nil, 0o755))
				require.NoError(t, os.WriteFile(gradlewBatPath, nil, 0o755))

				// Mock the specified OS
				originalDetector := osDetector
				osDetector = func() string { return tc.mockOS }
				defer func() { osDetector = originalDetector }()

				binary, err := ResolveGradleBinary(dir, false)
				require.NoError(t, err)

				expectedPath := filepath.Join(dir, tc.expectedWrapper)
				assert.Equal(t, expectedPath, binary)
			})
		}
	})

	t.Run("skip wrapper flag bypasses wrapper discovery", func(t *testing.T) {
		cleanup := setupFakeGradle(t)
		defer cleanup()

		dir := t.TempDir()
		wrapperPath := filepath.Join(dir, "gradlew")
		require.NoError(t, os.WriteFile(wrapperPath, nil, 0o755))

		// Even though wrapper exists, should skip it when flag is true
		binary, err := ResolveGradleBinary(dir, true)
		require.NoError(t, err)
		assert.Contains(t, binary, "gradle")
		assert.NotEqual(t, wrapperPath, binary)
	})

	t.Run("finds wrapper in parent directory", func(t *testing.T) {
		testCases := []struct {
			name        string
			mockOS      string
			wrapperName string
		}{
			{"windows", "windows", "gradlew.bat"},
			{"unix", "linux", "gradlew"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				parentDir := t.TempDir()
				childDir := filepath.Join(parentDir, "subproject")
				require.NoError(t, os.MkdirAll(childDir, 0o755))

				// Mock the specified OS
				originalDetector := osDetector
				osDetector = func() string { return tc.mockOS }
				defer func() { osDetector = originalDetector }()

				wrapperPath := filepath.Join(parentDir, tc.wrapperName)
				require.NoError(t, os.WriteFile(wrapperPath, nil, 0o755))

				// Should find wrapper by walking up from childDir (project directory)
				binary, err := ResolveGradleBinary(childDir, false)
				require.NoError(t, err)

				// Use filepath.Base comparison to avoid symlink path differences on macOS
				assert.Equal(t, tc.wrapperName, filepath.Base(binary))
				assert.Contains(t, binary, parentDir)
			})
		}
	})

	t.Run("returns error when gradle not found and no wrapper", func(t *testing.T) {
		// Save original PATH and set it to empty to simulate gradle not found
		originalPath := os.Getenv("PATH")
		require.NoError(t, os.Setenv("PATH", ""))
		defer os.Setenv("PATH", originalPath)

		dir := t.TempDir()
		binary, err := ResolveGradleBinary(dir, false)

		assert.Error(t, err)
		assert.Equal(t, errGradleNotFound, err)
		assert.Empty(t, binary)
	})
}
