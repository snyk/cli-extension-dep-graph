package uv

import (
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestHelper compiles the test helper binary and returns its path.
// The binary is built in a temporary directory and cleaned up after the test.
func buildTestHelper(t *testing.T) string {
	t.Helper()

	helperDir := filepath.Join("testdata", "testhelper")
	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "testhelper")

	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = helperDir
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to build test helper: %s", string(output))

	return binaryPath
}

func TestDefaultCmdExecutor(t *testing.T) {
	helperBin := buildTestHelper(t)
	version := formatVersion(minVersion)
	t.Setenv("TESTHELPER_VERSION", version)

	t.Run("returns stdout only", func(t *testing.T) {
		executor := &uvCmdExecutor{}

		expectedOutput := `{"bomFormat":"CycloneDX","specVersion":"1.5"}`
		output, err := executor.Execute(helperBin, ".", "-stdout", expectedOutput)

		require.NoError(t, err)
		assert.Equal(t, expectedOutput, string(output))
	})

	t.Run("ignores stderr when command succeeds", func(t *testing.T) {
		executor := &uvCmdExecutor{}

		stderrContent := "warning: some deprecation notice"
		output, err := executor.Execute(helperBin, ".", "-stderr", stderrContent)

		require.NoError(t, err)
		assert.Empty(t, output)
	})

	t.Run("returns stdout and ignores stderr when both present", func(t *testing.T) {
		executor := &uvCmdExecutor{}

		stdoutContent := `{"valid":"json"}`
		stderrContent := "warning: something"

		output, err := executor.Execute(helperBin, ".",
			"-stdout", stdoutContent,
			"-stderr", stderrContent,
		)

		require.NoError(t, err)

		assert.Equal(t, stdoutContent, string(output),
			"output should contain only stdout, not stderr")
	})

	t.Run("includes stdout and stderr in error on non-zero exit", func(t *testing.T) {
		executor := &uvCmdExecutor{}

		stdoutContent := "partial output before failure"
		stderrContent := "error: something went wrong"
		_, err := executor.Execute(helperBin, ".",
			"-stdout", stdoutContent,
			"-stderr", stderrContent,
			"-exit", "1",
		)

		require.Error(t, err)
		var catalogErr snyk_errors.Error
		require.True(t, errors.As(err, &catalogErr), "error should be a catalog error")
		assert.Contains(t, catalogErr.Detail, stdoutContent)
		assert.Contains(t, catalogErr.Detail, stderrContent)
	})

	t.Run("returns error when binary not found", func(t *testing.T) {
		executor := &uvCmdExecutor{}

		_, err := executor.Execute("binary-that-does-not-exist", ".")

		require.Error(t, err)
		var catalogErr snyk_errors.Error
		require.True(t, errors.As(err, &catalogErr), "error should be a catalog error")
		assert.Contains(t, catalogErr.Detail, "binary not found in PATH")
	})

	t.Run("executes in specified working directory", func(t *testing.T) {
		executor := &uvCmdExecutor{}

		// Create a temp directory to use as working directory
		tempDir := t.TempDir()

		output, err := executor.Execute(helperBin, tempDir, "-stdout", "ok")

		require.NoError(t, err)
		assert.Equal(t, "ok", string(output))
	})

	t.Run("handles empty output", func(t *testing.T) {
		executor := &uvCmdExecutor{}

		output, err := executor.Execute(helperBin, ".")

		require.NoError(t, err)
		assert.Empty(t, output)
	})
}

func TestParseAndValidateVersion_ValidVersions(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"exact minimum", "uv 0.9.11"},
		{"patch higher", "uv 0.9.12"},
		{"minor higher", "uv 0.10.0"},
		{"major higher", "uv 1.0.0"},
		{"with commit hash", "uv 0.9.11 (982851bf9)"},
		{"with commit hash and suffix", "uv 0.9.11+43 (982851bf9 2025-11-13)"},
		{"without prefix", "0.9.11"},
		{"future version", "uv 2.5.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseAndValidateVersion("uv", tt.output)
			assert.NoError(t, err)
		})
	}
}

func TestParseAndValidateVersion_InvalidVersions(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"patch too low", "uv 0.9.9"},
		{"exact one below minimum", "uv 0.9.10"},
		{"minor too low", "uv 0.8.21"},
		{"major and minor both 0", "uv 0.0.1"},
		{"minor too low with commit hash", "uv 0.9.9 (982851bf9)"},
		{"minor too low with commit hash and suffix", "uv 0.9.9+43 (982851bf9 2025-11-13)"},
		{"one below minimum with commit hash", "uv 0.9.10 (982851bf9)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseAndValidateVersion("uv", tt.output)
			require.Error(t, err)
			var catalogErr snyk_errors.Error
			assert.True(t, errors.As(err, &catalogErr), "error should be a catalog error")
			assert.Contains(t, catalogErr.Detail, "not supported")
			assert.Contains(t, catalogErr.Detail, "0.9.11")
		})
	}
}

func TestParseAndValidateVersion_UnparseableOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"no version", "uv command not found"},
		{"invalid format", "version: abc"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseAndValidateVersion("uv", tt.output)
			require.Error(t, err)
			var catalogErr snyk_errors.Error
			assert.True(t, errors.As(err, &catalogErr), "error should be a catalog error")
			assert.Contains(t, catalogErr.Detail, "unable to parse")
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       Version
		v2       Version
		expected int
	}{
		{"equal versions", Version{1, 2, 3}, Version{1, 2, 3}, 0},
		{"v1 less than v2 major", Version{0, 2, 3}, Version{1, 2, 3}, -1},
		{"v1 less than v2 minor", Version{1, 1, 3}, Version{1, 2, 3}, -1},
		{"v1 less than v2 patch", Version{1, 2, 2}, Version{1, 2, 3}, -1},
		{"v1 greater than v2 major", Version{2, 0, 0}, Version{1, 9, 9}, 1},
		{"v1 greater than v2 minor", Version{1, 3, 0}, Version{1, 2, 9}, 1},
		{"v1 greater than v2 patch", Version{1, 2, 4}, Version{1, 2, 3}, 1},
		{"exact minimum check", Version{0, 9, 10}, Version{0, 9, 10}, 0},
		{"one below minimum", Version{0, 9, 9}, Version{0, 9, 10}, -1},
		{"one above minimum", Version{0, 9, 11}, Version{0, 9, 10}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersions(tt.v1, tt.v2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  Version
		expected string
	}{
		{"single digit components", Version{1, 2, 3}, "1.2.3"},
		{"multi digit components", Version{10, 25, 100}, "10.25.100"},
		{"version with zeros", Version{1, 0, 50}, "1.0.50"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatVersion(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}
