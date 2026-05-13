//go:build !integration

package gradle

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDependencyGraphJSON(t *testing.T) {
	t.Run("parses valid JSON with a single project", func(t *testing.T) {
		input := []byte(`{"gradleVersion":"8.5","javaVersion":"17.0.9","generatedAt":"2024-01-01T00:00:00Z","rootProject":{"name":"my-app","group":"com.example","version":"1.0.0","path":"/projects/my-app"}}
{"name":"my-app","group":"com.example","version":"1.0.0","path":":","gav":"com.example:my-app:1.0.0","buildFile":"/projects/my-app/build.gradle","configurations":[{"name":"runtimeClasspath","description":"Runtime classpath","root":{"id":"com.example:my-app:1.0.0","dependencies":[{"id":"com.google.guava:guava:32.1.2-jre","dependencies":[]}]},"allDependencies":[]}]}`)

		result, err := parseDependencyGraphJSON(bytes.NewReader(input))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "8.5", result.Metadata.GradleVersion)
		assert.Equal(t, "my-app", result.Metadata.RootProject.Name)
		require.Len(t, result.Projects, 1)

		proj := result.Projects[0] // Should be the root project with path ":"
		assert.Equal(t, ":", proj.Path)
		assert.Equal(t, "com.example:my-app:1.0.0", proj.GAV)
		assert.Equal(t, "/projects/my-app/build.gradle", proj.BuildFile)
		require.Len(t, proj.Configurations, 1)

		cfg := proj.Configurations[0] // Should be the runtimeClasspath config
		assert.Equal(t, "runtimeClasspath", cfg.Name)
		assert.Equal(t, "com.example:my-app:1.0.0", cfg.Root.ID)
		require.Len(t, cfg.Root.Dependencies, 1)
		assert.Equal(t, "com.google.guava:guava:32.1.2-jre", cfg.Root.Dependencies[0].ID)
	})

	t.Run("parses multiple projects", func(t *testing.T) {
		input := []byte(`{"gradleVersion":"8.5","javaVersion":"17","generatedAt":"","rootProject":{"name":"root","group":"","version":"","path":""}}
{"name":"root","group":"com.example","version":"1.0","path":":","gav":"com.example:root:1.0","buildFile":"","configurations":[]}
{"name":"app","group":"com.example","version":"1.0","path":":app","gav":"com.example:app:1.0","buildFile":"","configurations":[]}`)

		result, err := parseDependencyGraphJSON(bytes.NewReader(input))
		require.NoError(t, err)
		assert.Len(t, result.Projects, 2)

		// Check that we have both projects in the array
		var foundRoot, foundApp bool
		for _, proj := range result.Projects {
			if proj.Path == ":" {
				foundRoot = true
			} else if proj.Path == ":app" {
				foundApp = true
			}
		}
		assert.True(t, foundRoot, "should contain root project")
		assert.True(t, foundApp, "should contain app project")
	})

	t.Run("parses pruned, constraint and unresolved dependencies", func(t *testing.T) {
		input := []byte(`{"gradleVersion":"8.5","javaVersion":"17","generatedAt":"","rootProject":{"name":"root","group":"","version":"","path":""}}
{"name":"root","group":"com.example","version":"1.0","path":":","gav":"com.example:root:1.0","buildFile":"","configurations":[{"name":"runtimeClasspath","description":"","root":{"id":"com.example:root:1.0","dependencies":[{"id":"com.example:a:1.0","pruned":"cycle","dependencies":[]},{"id":"com.example:b:1.0","pruned":"visited","dependencies":[]},{"id":"com.example:c:1.0","unresolved":true,"reason":"not found","dependencies":[]},{"id":"com.example:d:1.0","constraint":true}]},"allDependencies":[]}]}`)

		result, err := parseDependencyGraphJSON(bytes.NewReader(input))
		require.NoError(t, err)

		deps := result.Projects[0].Configurations[0].Root.Dependencies
		require.Len(t, deps, 4)
		assert.Equal(t, pruneCycle, deps[0].Pruned)
		assert.Equal(t, pruneVisited, deps[1].Pruned)
		assert.True(t, deps[2].Pruned.IsEmpty())
		assert.True(t, deps[2].Unresolved)
		assert.Equal(t, "not found", deps[2].Reason)
		assert.True(t, deps[3].Constraint)
		assert.True(t, deps[3].Pruned.IsEmpty())
		assert.False(t, deps[3].Unresolved)
	})

	t.Run("parses configuration error field", func(t *testing.T) {
		input := []byte(`{"gradleVersion":"8.5","javaVersion":"17","generatedAt":"","rootProject":{"name":"root","group":"","version":"","path":""}}
{"name":"root","group":"","version":"1.0","path":":","gav":":root:1.0","buildFile":"","configurations":[{"name":"brokenConfig","description":"","root":{"id":"","dependencies":[]},"allDependencies":[],"error":"resolution failed"}]}`)

		result, err := parseDependencyGraphJSON(bytes.NewReader(input))
		require.NoError(t, err)

		var brokenConfig gradleConfig = result.Projects[0].Configurations[0]
		require.Equal(t, "brokenConfig", brokenConfig.Name)
		assert.Equal(t, "resolution failed", brokenConfig.Error)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		_, err := parseDependencyGraphJSON(bytes.NewReader([]byte(`not valid json`)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse")
	})

	t.Run("returns error for empty input", func(t *testing.T) {
		_, err := parseDependencyGraphJSON(bytes.NewReader([]byte(``)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NDJSON output is empty")
	})

	t.Run("returns error for file with only blank lines", func(t *testing.T) {
		_, err := parseDependencyGraphJSON(bytes.NewReader([]byte("\n\n\n")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "NDJSON output is empty")
	})
}
