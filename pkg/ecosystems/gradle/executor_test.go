//go:build !integration

package gradle

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── parseSnykDepsMarker ───────────────────────────────────────────────────────

func TestParseSnykDepsMarker(t *testing.T) {
	t.Run("extracts path from marker line", func(t *testing.T) {
		output := "some gradle output\nSNYK_DEPS_JSON /tmp/snyk-deps-12345.json\nmore output\n"
		assert.Equal(t, "/tmp/snyk-deps-12345.json", parseSnykDepsMarker(output))
	})

	t.Run("handles Windows-style path", func(t *testing.T) {
		output := "SNYK_DEPS_JSON C:\\build\\reports\\snyk-dependency-graph.json\n"
		assert.Equal(t, `C:\build\reports\snyk-dependency-graph.json`, parseSnykDepsMarker(output))
	})

	t.Run("ignores leading and trailing whitespace on marker line", func(t *testing.T) {
		// TrimSpace is applied to each line, so both leading and trailing
		// whitespace are stripped before the prefix check and extraction.
		output := "  SNYK_DEPS_JSON /tmp/file.json  \n"
		assert.Equal(t, "/tmp/file.json", parseSnykDepsMarker(output))
	})

	t.Run("returns empty string when marker is absent", func(t *testing.T) {
		output := "Task :snykDependencyGraph\nBUILD SUCCESSFUL\n"
		assert.Equal(t, "", parseSnykDepsMarker(output))
	})

	t.Run("returns empty string for empty output", func(t *testing.T) {
		assert.Equal(t, "", parseSnykDepsMarker(""))
	})

	t.Run("uses first marker line when multiple present", func(t *testing.T) {
		output := "SNYK_DEPS_JSON /first.json\nSNYK_DEPS_JSON /second.json\n"
		assert.Equal(t, "/first.json", parseSnykDepsMarker(output))
	})
}
