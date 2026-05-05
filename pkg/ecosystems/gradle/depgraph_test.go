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
func makeProject(group, name, version string, configs []gradleConfig) gradleProject {
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

func makeConfig(name string, rootID string, deps []gradleDep) gradleConfig {
	return gradleConfig{
		Name: name,
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
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
			makeConfig("compileClasspath", "com.example:my-app:1.0.0", []gradleDep{
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
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.junit.jupiter:junit-jupiter:5.10.0"),
			}),
			makeConfig("testRuntimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
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
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
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

	t.Run("handles cycle-pruned dependencies as pruned nodes", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "com.example:a:1.0.0", Pruned: pruneCycle},
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:a@1.0.0:pruned"], "cycle-pruned dep should appear as pruned node")
		assert.False(t, ids["com.example:a@1.0.0"], "cycle-pruned dep should not appear as normal node")
	})

	t.Run("handles visited-pruned dependencies as pruned nodes", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "com.example:b:2.0.0", Pruned: pruneVisited},
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:b@2.0.0:pruned"], "visited-pruned dep should appear as pruned node")
		assert.False(t, ids["com.example:b@2.0.0"], "visited-pruned dep should not appear as normal node")
	})

	t.Run("skips unresolved dependencies", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
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
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			{Name: "runtimeClasspath", Error: "resolution failed"},
			makeConfig("compileClasspath", "com.example:app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "deps from valid config should be present")
	})

	t.Run("returns empty graph when all configurations have errors", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			{Name: "runtimeClasspath", Error: "resolution failed"},
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		// Only the root node; no dependency nodes.
		assert.Len(t, dg.Graph.Nodes, 1)
	})

	t.Run("returns empty graph when no configurations present", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)
		assert.Len(t, dg.Graph.Nodes, 1)
	})

	t.Run("uses empty string for 'unspecified' version", func(t *testing.T) {
		proj := makeProject("com.example", "app", "unspecified", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:unspecified", []gradleDep{}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)
		assert.Equal(t, "", dg.Pkgs[0].Info.Version)
	})

	t.Run("prunes subsequent references to same dependency per configuration", func(t *testing.T) {
		// This test simulates the common case where two parents reference the same child.
		// The init script would emit the child's full subtree under the first parent and
		// mark subsequent references as pruned: "visited".
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:a:1.0.0", makeDep("com.example:c:1.0.0")),
				makeDep("com.example:b:1.0.0", gradleDep{ID: "com.example:c:1.0.0", Pruned: pruneVisited}),
			}),
		})

		dg, err := buildDepGraph(&proj)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:c@1.0.0"], "first occurrence should appear as normal node")
		assert.True(t, ids["com.example:c@1.0.0:pruned"], "subsequent occurrence should appear as pruned node")
	})

	t.Run("preserves different versions of same transitive dependency across configurations", func(t *testing.T) {
		// This test ensures we avoid the cross-configuration contamination issue where
		// different configurations with different resolved versions of the same transitive
		// dependency would interfere with each other.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:lib:1.2.3",
					makeDep("com.fasterxml.jackson.core:jackson-core:2.19.0")),
			}),
			makeConfig("intellijPlatformTestClasspath", "com.example:app:1.0.0", []gradleDep{
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

// TestBuildDepGraph_DoesNotDuplicateEdges asserts that when the same
// (parent, child) edge is contributed by multiple Gradle configurations
// (e.g. a dep present in compileClasspath, runtimeClasspath,
// testCompileClasspath and testRuntimeClasspath), the merged graph contains
// the edge exactly once.
func TestBuildDepGraph_DoesNotDuplicateEdges(t *testing.T) {
	proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
		makeConfig("compileClasspath", "com.example:app:1.0.0", []gradleDep{makeDep("com.google.guava:guava:32.1.2-jre")}),
		makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{makeDep("com.google.guava:guava:32.1.2-jre")}),
		makeConfig("testCompileClasspath", "com.example:app:1.0.0", []gradleDep{makeDep("com.google.guava:guava:32.1.2-jre")}),
		makeConfig("testRuntimeClasspath", "com.example:app:1.0.0", []gradleDep{makeDep("com.google.guava:guava:32.1.2-jre")}),
	})

	dg, err := buildDepGraph(&proj)
	require.NoError(t, err)

	rootNode := findNodeByID(t, dg, "root-node")
	guavaEdges := countEdgesTo(rootNode, "com.google.guava:guava@32.1.2-jre")
	assert.Equal(t, 1, guavaEdges,
		"shared dep should appear exactly once on root despite being present in %d configurations", len(proj.Configurations))
}

// findNodeByID returns the node with the given ID, failing the test if it is
// not present.
func findNodeByID(t *testing.T, dg *depgraph.DepGraph, id string) *depgraph.Node {
	t.Helper()
	for i := range dg.Graph.Nodes {
		if dg.Graph.Nodes[i].NodeID == id {
			return &dg.Graph.Nodes[i]
		}
	}
	require.Failf(t, "node not found", "node %q not present in graph", id)
	return nil
}

// countEdgesTo returns how many times childID appears as a direct child of node.
func countEdgesTo(node *depgraph.Node, childID string) int {
	count := 0
	for _, dep := range node.Deps {
		if dep.NodeID == childID {
			count++
		}
	}
	return count
}

// TestBuildDepGraph_EdgePositionFromFirstDeclaringConfig asserts that when an
// edge is contributed by multiple configurations, its position in the parent's
// Deps slice is taken from the first configuration in evaluation order that contributes
// it. This documents the merge rule: configurations are walked in Gradle's natural
// evaluation order and an edge keeps the position it was first inserted at.
func TestBuildDepGraph_EdgePositionFromFirstDeclaringConfig(t *testing.T) {
	// Test that edge positions are taken from the first configuration that declares them.
	// compileClasspath has guava first, commons-lang3 second.
	// runtimeClasspath has commons-lang3 first, guava second.
	// Since compileClasspath is processed first, the merged deps should follow compileClasspath's order.
	compileConfig := makeConfig("compileClasspath", "com.example:app:1.0.0", []gradleDep{
		makeDep("com.google.guava:guava:32.1.2-jre"),
		makeDep("org.apache.commons:commons-lang3:3.14.0"),
	})

	runtimeConfig := makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
		makeDep("org.apache.commons:commons-lang3:3.14.0"),
		makeDep("com.google.guava:guava:32.1.2-jre"),
	})

	proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{compileConfig, runtimeConfig})

	dg, err := buildDepGraph(&proj)
	require.NoError(t, err)

	rootNode := findNodeByID(t, dg, "root-node")
	require.Len(t, rootNode.Deps, 2, "duplicates across configs should be merged")
	assert.Equal(t, "com.google.guava:guava@32.1.2-jre", rootNode.Deps[0].NodeID,
		"position should be taken from compileClasspath (first config), which has guava first")
	assert.Equal(t, "org.apache.commons:commons-lang3@3.14.0", rootNode.Deps[1].NodeID)
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
