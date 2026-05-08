//go:build !integration

package gradle

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── parseSnykDepsMarkerFromStream ───────────────────────────────────────────────────────

func TestParseSnykDepsMarkerFromStream(t *testing.T) {
	t.Run("extracts path from marker line", func(t *testing.T) {
		output := "some gradle output\nSNYK_DEPS_NDJSON /tmp/snyk-deps-12345.ndjson\nmore output\n"
		result, err := parseSnykDepsMarkerFromStream(strings.NewReader(output))
		require.NoError(t, err)
		assert.Equal(t, "/tmp/snyk-deps-12345.ndjson", result)
	})

	t.Run("handles Windows-style path", func(t *testing.T) {
		output := "SNYK_DEPS_NDJSON C:\\build\\reports\\snyk-dependency-graph.ndjson\n"
		result, err := parseSnykDepsMarkerFromStream(strings.NewReader(output))
		require.NoError(t, err)
		assert.Equal(t, `C:\build\reports\snyk-dependency-graph.ndjson`, result)
	})

	t.Run("ignores leading and trailing whitespace on marker line", func(t *testing.T) {
		// TrimSpace is applied to each line, so both leading and trailing
		// whitespace are stripped before the prefix check and extraction.
		output := "  SNYK_DEPS_NDJSON /tmp/file.ndjson  \n"
		result, err := parseSnykDepsMarkerFromStream(strings.NewReader(output))
		require.NoError(t, err)
		assert.Equal(t, "/tmp/file.ndjson", result)
	})

	t.Run("returns empty string when marker is absent", func(t *testing.T) {
		output := "Task :snykDependencyGraph\nBUILD SUCCESSFUL\n"
		result, err := parseSnykDepsMarkerFromStream(strings.NewReader(output))
		require.NoError(t, err)
		assert.Equal(t, "", result)
	})

	t.Run("returns empty string for empty output", func(t *testing.T) {
		result, err := parseSnykDepsMarkerFromStream(strings.NewReader(""))
		require.NoError(t, err)
		assert.Equal(t, "", result)
	})

	t.Run("returns error when multiple marker lines detected", func(t *testing.T) {
		output := "SNYK_DEPS_NDJSON /first.ndjson\nSNYK_DEPS_NDJSON /second.ndjson\n"
		result, err := parseSnykDepsMarkerFromStream(strings.NewReader(output))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "multiple SNYK_DEPS_NDJSON marker lines detected")
		assert.Contains(t, err.Error(), "possible tampering attempt")
		assert.Empty(t, result)
	})

	t.Run("returns error even when multiple markers are separated by other output", func(t *testing.T) {
		output := "Task :snykDependencyGraph\nSNYK_DEPS_NDJSON /first.ndjson\nBUILD SUCCESSFUL\nSNYK_DEPS_NDJSON /second.ndjson\nDone\n"
		result, err := parseSnykDepsMarkerFromStream(strings.NewReader(output))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "multiple SNYK_DEPS_NDJSON marker lines detected")
		assert.Empty(t, result)
	})
}
