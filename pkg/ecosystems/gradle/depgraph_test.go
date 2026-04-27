//go:build !integration

package gradle

import (
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nodeIDSet returns the set of all node IDs present in the dep graph, making
// it easy to assert presence or absence of a dependency.
func nodeIDSet(dg *depgraph.DepGraph) map[string]bool {
	result := make(map[string]bool)
	for _, node := range dg.Graph.Nodes {
		result[node.NodeID] = true
	}

	return result
}

// makeProject is a test helper that builds a gradleProject with the given configurations.
func makeProject(group, name, version string, configs map[string]gradleConfig) gradleProject {
	gav := group + ":" + name + ":" + version
	return gradleProject{
		Name:           name,
		Group:          group,
		Version:        version,
		Path:           ":",
		GAV:            gav,
		BuildFile:      "build.gradle",
		Configurations: configs,
	}
}

func makeConfig(rootID string, deps []gradleDep) gradleConfig {
	return gradleConfig{
		Root: configRoot{
			ID:           rootID,
			Dependencies: deps,
		},
	}
}

func makeDep(id string, children ...gradleDep) gradleDep {
	return gradleDep{ID: id, Dependencies: children}
}

// ── buildDepGraph ─────────────────────────────────────────────────────────────

func TestBuildDepGraph(t *testing.T) {
	t.Run("merges deps from all configurations into one graph", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": makeConfig("com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
			"compileClasspath": makeConfig("com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.apache.commons:commons-lang3:3.12.0"),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)
		require.NotNil(t, dg)

		assert.Equal(t, "gradle", dg.PkgManager.Name)
		assert.Equal(t, "com.example:my-app", dg.Pkgs[0].Info.Name)
		assert.Equal(t, "1.0.0", dg.Pkgs[0].Info.Version)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "runtimeClasspath dep should be included")
		assert.True(t, ids["org.apache.commons:commons-lang3@3.12.0"], "compileClasspath dep should also be included")
	})

	t.Run("includes test configurations", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", map[string]gradleConfig{
			"testRuntimeClasspath": makeConfig("com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.junit.jupiter:junit-jupiter:5.10.0"),
			}),
			"runtimeClasspath": makeConfig("com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"])
		assert.True(t, ids["org.junit.jupiter:junit-jupiter@5.10.0"], "test configuration deps should be merged in")
	})

	t.Run("includes transitive dependencies", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": makeConfig("com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:lib:1.0.0",
					makeDep("org.slf4j:slf4j-api:2.0.0"),
				),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:lib@1.0.0"])
		assert.True(t, ids["org.slf4j:slf4j-api@2.0.0"])
	})

	t.Run("handles circular dependencies as pruned nodes", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": makeConfig("com.example:app:1.0.0", []gradleDep{
				{ID: "com.example:a:1.0.0", Circular: true},
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:a@1.0.0:pruned"], "circular dep should appear as pruned node")
		assert.False(t, ids["com.example:a@1.0.0"], "circular dep should not appear as normal node")
	})

	t.Run("skips unresolved dependencies", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": makeConfig("com.example:app:1.0.0", []gradleDep{
				{ID: "com.example:missing:1.0.0", Unresolved: true, Reason: "not found"},
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.False(t, ids["com.example:missing@1.0.0"], "unresolved dep should be skipped")
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "resolved dep should be present")
	})

	t.Run("skips configurations with errors", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": {Error: "resolution failed"},
			"compileClasspath": makeConfig("com.example:app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "deps from valid config should be present")
	})

	t.Run("returns empty graph when all configurations have errors", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": {Error: "resolution failed"},
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		// Only the root node; no dependency nodes.
		assert.Len(t, dg.Graph.Nodes, 1)
	})

	t.Run("returns empty graph when no configurations present", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)
		assert.Len(t, dg.Graph.Nodes, 1)
	})

	t.Run("uses empty string for 'unspecified' version", func(t *testing.T) {
		proj := makeProject("com.example", "app", "unspecified", map[string]gradleConfig{
			"runtimeClasspath": makeConfig("com.example:app:unspecified", []gradleDep{}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)
		assert.Equal(t, "", dg.Pkgs[0].Info.Version)
	})

	t.Run("does not prune a dependency reached from multiple parents", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": makeConfig("com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:a:1.0.0", makeDep("com.example:c:1.0.0")),
				makeDep("com.example:b:1.0.0", makeDep("com.example:c:1.0.0")),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:c@1.0.0"], "shared dep should appear in graph")
		assert.False(t, ids["com.example:c@1.0.0:pruned"], "shared dep should NOT be pruned when it is not circular")
	})

	t.Run("preserves different versions of same transitive dependency across configurations", func(t *testing.T) {
		// This test ensures we avoid the cross-configuration contamination issue where
		// different configurations with different resolved versions of the same transitive
		// dependency would interfere with each other.
		proj := makeProject("com.example", "app", "1.0.0", map[string]gradleConfig{
			"runtimeClasspath": makeConfig("com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:lib:1.2.3",
					makeDep("com.fasterxml.jackson.core:jackson-core:2.19.0")),
			}),
			"intellijPlatformTestClasspath": makeConfig("com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:lib:1.2.3",
					makeDep("com.fasterxml.jackson.core:jackson-core:2.17.0")),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)

		// Both configurations should contribute their dependencies
		assert.True(t, ids["com.example:lib@1.2.3"], "direct dependency should be present")
		assert.True(t, ids["com.fasterxml.jackson.core:jackson-core@2.19.0"], "jackson 2.19.0 from runtimeClasspath should be present")
		assert.True(t, ids["com.fasterxml.jackson.core:jackson-core@2.17.0"], "jackson 2.17.0 from intellijPlatformTestClasspath should be present")

		// Verify neither version was pruned due to cross-configuration contamination
		assert.False(t, ids["com.fasterxml.jackson.core:jackson-core@2.19.0:pruned"], "jackson 2.19.0 should not be pruned")
		assert.False(t, ids["com.fasterxml.jackson.core:jackson-core@2.17.0:pruned"], "jackson 2.17.0 should not be pruned")

		// Verify both jackson versions are children of lib - this is the key behavior that would
		// demonstrate the cross-configuration merging issue if it existed
		var libNode *depgraph.Node
		for _, node := range dg.Graph.Nodes {
			if node.NodeID == "com.example:lib@1.2.3" {
				libNode = &node
				break
			}
		}
		require.NotNil(t, libNode, "lib node should exist")
		
		libChildren := make(map[string]bool)
		for _, dep := range libNode.Deps {
			libChildren[dep.NodeID] = true
		}
		assert.True(t, libChildren["com.fasterxml.jackson.core:jackson-core@2.19.0"], "jackson 2.19.0 should be child of lib")
		assert.True(t, libChildren["com.fasterxml.jackson.core:jackson-core@2.17.0"], "jackson 2.17.0 should be child of lib")
	})
}

// ── depNodeParts ──────────────────────────────────────────────────────────────

func TestDepNodeParts(t *testing.T) {
	tests := []struct {
		id          string
		wantNodeID  string
		wantName    string
		wantVersion string
	}{
		{
			id:          "com.google.guava:guava:32.1.2-jre",
			wantNodeID:  "com.google.guava:guava@32.1.2-jre",
			wantName:    "com.google.guava:guava",
			wantVersion: "32.1.2-jre",
		},
		{
			id:          "org.springframework:spring-core:6.0.0",
			wantNodeID:  "org.springframework:spring-core@6.0.0",
			wantName:    "org.springframework:spring-core",
			wantVersion: "6.0.0",
		},
		{
			id:          "project :lib",
			wantNodeID:  "project :lib",
			wantName:    "project :lib",
			wantVersion: "",
		},
		{
			id:          "unrecognised",
			wantNodeID:  "unrecognised",
			wantName:    "unrecognised",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			nodeID, name, version := depNodeParts(tt.id)
			assert.Equal(t, tt.wantNodeID, nodeID)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

// ── splitGAV ──────────────────────────────────────────────────────────────────

func TestSplitGAV(t *testing.T) {
	tests := []struct {
		gav         string
		wantName    string
		wantVersion string
	}{
		{"com.example:my-app:1.0.0", "com.example:my-app", "1.0.0"},
		{"org.springframework:spring-core:6.0.0", "org.springframework:spring-core", "6.0.0"},
		{"noColons", "noColons", ""},
		{"only:two", "only:two", ""},
	}

	for _, tt := range tests {
		t.Run(tt.gav, func(t *testing.T) {
			name, version := splitGAV(tt.gav)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}
