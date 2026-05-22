//go:build !integration

package gradle

import (
	"testing"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
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

		dg, err := buildDepGraph(&proj, nil)
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

		dg, err := buildDepGraph(&proj, nil)
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

		dg, err := buildDepGraph(&proj, nil)
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

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:a@1.0.0:pruned"], "cycle-pruned dep should appear as pruned node")
		assert.False(t, ids["com.example:a@1.0.0"], "cycle-pruned dep should not appear as normal node")
	})

	t.Run("handles visited-pruned dependencies by connecting to existing nodes", func(t *testing.T) {
		// Test that visited-pruned dependencies connect to existing nodes instead of creating pruned versions.
		// We simulate a case where a node is expanded under one parent and then referenced as pruned under another.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:a:1.0.0", makeDep("com.example:shared:1.0.0")),                             // First occurrence - creates the node
				makeDep("com.example:b:1.0.0", gradleDep{ID: "com.example:shared:1.0.0", Pruned: pruneVisited}), // Second occurrence - should connect to existing
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:shared@1.0.0"], "visited-pruned dep should connect to existing node")
		assert.False(t, ids["com.example:shared@1.0.0:pruned"], "visited-pruned dep should not create pruned node")

		// Verify the shared node has two different parents
		aNode := findNodeByID(t, dg, "com.example:a@1.0.0")
		bNode := findNodeByID(t, dg, "com.example:b@1.0.0")

		sharedEdgesFromA := countEdgesTo(aNode, "com.example:shared@1.0.0")
		sharedEdgesFromB := countEdgesTo(bNode, "com.example:shared@1.0.0")

		assert.Equal(t, 1, sharedEdgesFromA, "a should reference shared node once")
		assert.Equal(t, 1, sharedEdgesFromB, "b should reference the same shared node")
	})

	t.Run("emits unresolved dependencies as labeled leaf nodes", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "com.example:missing:1.0.0", Unresolved: true, Reason: "Could not resolve com.example:missing:1.0.0"},
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:missing@1.0.0:unresolved"], "unresolved dep should appear as :unresolved leaf")
		assert.False(t, ids["com.example:missing@1.0.0"], "unresolved dep should not appear as a normal node")
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "resolved dep should still be present")

		unresolvedNode := findNodeByID(t, dg, "com.example:missing@1.0.0:unresolved")
		require.NotNil(t, unresolvedNode.Info)
		assert.Equal(t, "true", unresolvedNode.Info.Labels["unresolved"])
		_, hasReason := unresolvedNode.Info.Labels["reason"]
		assert.False(t, hasReason, "Gradle failure messages must not be copied onto dep-graph labels")
	})

	t.Run("unresolved dep node ID does not collide with a successfully-resolved node", func(t *testing.T) {
		// Under different configurations the same coordinate could resolve in one
		// and fail in another. Both nodes must coexist in the merged graph.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("compileClasspath", "com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:lib:1.0.0"),
			}),
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "com.example:lib:1.0.0", Unresolved: true, Reason: "content filter"},
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:lib@1.0.0"], "resolved node should be present")
		assert.True(t, ids["com.example:lib@1.0.0:unresolved"], "unresolved node should also be present under different ID")
	})

	t.Run("skips unresolved dep with empty ID", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "", Unresolved: true, Reason: "selector has no coordinate"},
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"])
		assert.Equal(t, 2, len(ids), "no node should be created for an empty-ID unresolved dep")
	})

	t.Run("renders constraint dependencies as labelled :constraint leaves", func(t *testing.T) {
		// Constraint edges (from platform BOMs, dependency locking, constraints {}
		// blocks) should appear as a separate suffixed node so consumers can
		// distinguish them from real artifact dependencies.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "com.google.code.gson:gson:2.8.2", Constraint: true},
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.code.gson:gson@2.8.2:constraint"], "constraint dep should appear as :constraint node")
		assert.False(t, ids["com.google.code.gson:gson@2.8.2"], "constraint-only dep should not also appear as a normal node")

		constraintNode := findNodeByID(t, dg, "com.google.code.gson:gson@2.8.2:constraint")
		require.NotNil(t, constraintNode.Info)
		assert.Equal(t, "true", constraintNode.Info.Labels["constraint"])
	})

	t.Run("constraint nodes are leaves and do not recurse", func(t *testing.T) {
		// Even if the init script were to (incorrectly) attach children to a
		// constraint node, addDep should not walk them — constraint edges are
		// always treated as leaves.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{
					ID:         "com.google.code.gson:gson:2.8.2",
					Constraint: true,
					Dependencies: []gradleDep{
						makeDep("should.not.appear:child:1.0.0"),
					},
				},
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.code.gson:gson@2.8.2:constraint"])
		assert.False(t, ids["should.not.appear:child@1.0.0"], "constraint nodes must not recurse")
	})

	t.Run("constraint edge does not poison visited set for real edge to same component", func(t *testing.T) {
		// Regression for the platform-BOM / lock-file case: a constraint edge
		// to module X must not cause a subsequent real edge to X to be treated
		// as already-visited. The real edge must still expand its full subtree.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "dom4j:dom4j:1.6.1", Constraint: true},
				makeDep("dom4j:dom4j:1.6.1", makeDep("xml-apis:xml-apis:1.4.01")),
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["dom4j:dom4j@1.6.1:constraint"], "constraint edge should produce :constraint node")
		assert.True(t, ids["dom4j:dom4j@1.6.1"], "real edge should still produce normal node")
		assert.True(t, ids["xml-apis:xml-apis@1.4.01"], "real edge subtree must expand fully")

		dom4jNode := findNodeByID(t, dg, "dom4j:dom4j@1.6.1")
		assert.Equal(t, 1, countEdgesTo(dom4jNode, "xml-apis:xml-apis@1.4.01"),
			"transitive child should be reachable via the real (non-constraint) parent")
	})

	t.Run("preserves emission order for mixed constraint and real edges", func(t *testing.T) {
		// When a parent has both constraint and real edges, their order in the
		// resulting Deps slice should match the input order from the init script.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				{ID: "com.example:locked:1.0.0", Constraint: true},
				makeDep("com.example:real:1.0.0"),
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		rootNode := findNodeByID(t, dg, "root-node")
		require.Len(t, rootNode.Deps, 2)
		assert.Equal(t, "com.example:locked@1.0.0:constraint", rootNode.Deps[0].NodeID)
		assert.Equal(t, "com.example:real@1.0.0", rootNode.Deps[1].NodeID)
	})

	t.Run("skips configurations with errors", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			{Name: "runtimeClasspath", Error: "resolution failed"},
			makeConfig("compileClasspath", "com.example:app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "deps from valid config should be present")
	})

	t.Run("returns empty graph when all configurations have errors", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			{Name: "runtimeClasspath", Error: "resolution failed"},
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		// Only the root node; no dependency nodes.
		assert.Len(t, dg.Graph.Nodes, 1)
	})

	t.Run("returns empty graph when no configurations present", func(t *testing.T) {
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)
		assert.Len(t, dg.Graph.Nodes, 1)
	})

	t.Run("uses empty string for 'unspecified' version", func(t *testing.T) {
		proj := makeProject("com.example", "app", "unspecified", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:unspecified", []gradleDep{}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)
		assert.Equal(t, "", dg.Pkgs[0].Info.Version)
	})

	t.Run("connects subsequent references to same dependency per configuration", func(t *testing.T) {
		// This test simulates the common case where two parents reference the same child.
		// The init script would emit the child's full subtree under the first parent and
		// mark subsequent references as pruned: "visited". With DAG behavior, we connect
		// to the existing node instead of creating pruned versions.
		proj := makeProject("com.example", "app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:app:1.0.0", []gradleDep{
				makeDep("com.example:a:1.0.0", makeDep("com.example:c:1.0.0")),
				makeDep("com.example:b:1.0.0", gradleDep{ID: "com.example:c:1.0.0", Pruned: pruneVisited}),
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.example:c@1.0.0"], "dependency should appear as normal node")
		assert.False(t, ids["com.example:c@1.0.0:pruned"], "should not create pruned version for visited nodes")

		// Verify both parents reference the same node
		aNode := findNodeByID(t, dg, "com.example:a@1.0.0")
		bNode := findNodeByID(t, dg, "com.example:b@1.0.0")

		cEdgesFromA := countEdgesTo(aNode, "com.example:c@1.0.0")
		cEdgesFromB := countEdgesTo(bNode, "com.example:c@1.0.0")

		assert.Equal(t, 1, cEdgesFromA, "a should reference c once")
		assert.Equal(t, 1, cEdgesFromB, "b should reference the same c node")
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

		dg, err := buildDepGraph(&proj, nil)
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

	dg, err := buildDepGraph(&proj, nil)
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

	dg, err := buildDepGraph(&proj, nil)
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

// ── Configuration Matching Tests ─────────────────────────────────────────────

func TestBuildDepGraph_ConfigurationMatching(t *testing.T) {
	t.Run("filters configurations by exact match", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
			makeConfig("compileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.apache.commons:commons-lang3:3.12.0"),
			}),
			makeConfig("testRuntimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("junit:junit:4.13.2"),
			}),
		})

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "runtimeClasspath"

		dg, err := buildDepGraph(&proj, options)
		require.NoError(t, err)
		require.NotNil(t, dg)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "runtimeClasspath dep should be included")
		assert.False(t, ids["org.apache.commons:commons-lang3@3.12.0"], "compileClasspath dep should be excluded")
		assert.False(t, ids["junit:junit@4.13.2"], "testRuntimeClasspath dep should be excluded")
	})

	t.Run("filters configurations by regex pattern", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
			makeConfig("compileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.apache.commons:commons-lang3:3.12.0"),
			}),
			makeConfig("testRuntimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("junit:junit:4.13.2"),
			}),
			makeConfig("testCompileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.mockito:mockito-core:5.1.1"),
			}),
		})

		// Match all runtime classpaths (runtime and testRuntime) - case insensitive
		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "(?i).*runtime.*"

		dg, err := buildDepGraph(&proj, options)
		require.NoError(t, err)
		require.NotNil(t, dg)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "runtimeClasspath dep should be included")
		assert.True(t, ids["junit:junit@4.13.2"], "testRuntimeClasspath dep should be included")
		assert.False(t, ids["org.apache.commons:commons-lang3@3.12.0"], "compileClasspath dep should be excluded")
		assert.False(t, ids["org.mockito:mockito-core@5.1.1"], "testCompileClasspath dep should be excluded")
	})

	t.Run("includes all configurations when no pattern specified", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
			makeConfig("compileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.apache.commons:commons-lang3:3.12.0"),
			}),
		})

		dg, err := buildDepGraph(&proj, nil)
		require.NoError(t, err)
		require.NotNil(t, dg)

		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "runtimeClasspath dep should be included")
		assert.True(t, ids["org.apache.commons:commons-lang3@3.12.0"], "compileClasspath dep should be included")
	})

	t.Run("returns error for invalid regex pattern", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{}),
		})

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "[invalid-regex"

		_, err := buildDepGraph(&proj, options)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
		assert.Contains(t, err.Error(), "[invalid-regex")
	})

	t.Run("returns empty graph when no configurations match pattern", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
			makeConfig("compileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.apache.commons:commons-lang3:3.12.0"),
			}),
		})

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "nonExistentConfiguration"

		dg, err := buildDepGraph(&proj, options)
		require.NoError(t, err)
		require.NotNil(t, dg)

		// Only the root node should exist; no dependency nodes.
		assert.Len(t, dg.Graph.Nodes, 1)
	})

	t.Run("preserves configuration processing order after filtering", func(t *testing.T) {
		// Test that when multiple configurations match, they are processed in their original order
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			makeConfig("compileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),       // First occurrence
				makeDep("org.apache.commons:commons-lang3:3.12.0"), // First occurrence
			}),
			makeConfig("runtimeClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("org.apache.commons:commons-lang3:3.12.0"), // Second occurrence (should be deduplicated)
				makeDep("com.google.guava:guava:32.1.2-jre"),       // Second occurrence (should be deduplicated)
			}),
			makeConfig("testCompileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("junit:junit:4.13.2"), // Should be excluded by pattern
			}),
		})

		// Match compile and runtime classpaths but not test
		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = "(compile|runtime)Classpath"

		dg, err := buildDepGraph(&proj, options)
		require.NoError(t, err)

		rootNode := findNodeByID(t, dg, "root-node")
		require.Len(t, rootNode.Deps, 2, "should have 2 dependencies from merged configurations")

		// Verify order is preserved from first configuration (compileClasspath)
		assert.Equal(t, "com.google.guava:guava@32.1.2-jre", rootNode.Deps[0].NodeID,
			"order should be preserved from first matching configuration")
		assert.Equal(t, "org.apache.commons:commons-lang3@3.12.0", rootNode.Deps[1].NodeID)

		// Verify test dependency is excluded
		ids := nodeIDSet(dg)
		assert.False(t, ids["junit:junit@4.13.2"], "test dependency should be excluded")
	})

	t.Run("handles configuration matching with configurations that have errors", func(t *testing.T) {
		proj := makeProject("com.example", "my-app", "1.0.0", []gradleConfig{
			{Name: "runtimeClasspath", Error: "resolution failed"},
			makeConfig("compileClasspath", "com.example:my-app:1.0.0", []gradleDep{
				makeDep("com.google.guava:guava:32.1.2-jre"),
			}),
		})

		options := &ecosystems.SCAPluginOptions{}
		options.Gradle.ConfigurationMatching = ".*Classpath"

		dg, err := buildDepGraph(&proj, options)
		require.NoError(t, err)

		// Only compileClasspath should contribute dependencies; runtimeClasspath has error
		ids := nodeIDSet(dg)
		assert.True(t, ids["com.google.guava:guava@32.1.2-jre"], "compileClasspath dep should be included")
	})
}

func TestFilterConfigurationsByPattern(t *testing.T) {
	configs := []gradleConfig{
		{Name: "runtimeClasspath"},
		{Name: "compileClasspath"},
		{Name: "testRuntimeClasspath"},
		{Name: "testCompileClasspath"},
		{Name: "annotationProcessor"},
	}

	t.Run("filters by exact match", func(t *testing.T) {
		filtered, err := filterConfigurationsByPattern(configs, "runtimeClasspath")
		require.NoError(t, err)
		require.Len(t, filtered, 1)
		assert.Equal(t, "runtimeClasspath", filtered[0].Name)
	})

	t.Run("filters by regex pattern", func(t *testing.T) {
		filtered, err := filterConfigurationsByPattern(configs, "(?i).*runtime.*")
		require.NoError(t, err)
		require.Len(t, filtered, 2)
		assert.Equal(t, "runtimeClasspath", filtered[0].Name)
		assert.Equal(t, "testRuntimeClasspath", filtered[1].Name)
	})

	t.Run("returns empty slice when no matches", func(t *testing.T) {
		filtered, err := filterConfigurationsByPattern(configs, "nonExistent")
		require.NoError(t, err)
		assert.Len(t, filtered, 0)
	})

	t.Run("returns error for invalid regex", func(t *testing.T) {
		_, err := filterConfigurationsByPattern(configs, "[invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("matches all with .* pattern", func(t *testing.T) {
		filtered, err := filterConfigurationsByPattern(configs, ".*")
		require.NoError(t, err)
		assert.Len(t, filtered, 5)
	})

	t.Run("returns all configurations when pattern is empty", func(t *testing.T) {
		filtered, err := filterConfigurationsByPattern(configs, "")
		require.NoError(t, err)
		assert.Len(t, filtered, 5)
		assert.Equal(t, configs, filtered) // Should return the exact same slice
	})
}

func TestCreatePkgInfo(t *testing.T) {
	t.Run("creates basic PkgInfo without provenance enabled", func(t *testing.T) {
		pkgInfo := createPkgInfo("org.example:artifact", "1.0.0", nil, false)

		assert.Equal(t, "org.example:artifact", pkgInfo.Name)
		assert.Equal(t, "1.0.0", pkgInfo.Version)
		assert.Empty(t, pkgInfo.PackageURL) // No PURL when provenance disabled
	})

	t.Run("creates PkgInfo with base PURL when provenance enabled but no provenance data", func(t *testing.T) {
		pkgInfo := createPkgInfo("org.example:artifact", "1.0.0", nil, true)

		assert.Equal(t, "org.example:artifact", pkgInfo.Name)
		assert.Equal(t, "1.0.0", pkgInfo.Version)
		assert.Equal(t, "pkg:maven/org.example/artifact@1.0.0", pkgInfo.PackageURL) // Base PURL when provenance enabled
	})

	t.Run("creates PkgInfo with checksum PURL when provenance available", func(t *testing.T) {
		provenanceEntry := &allDepEntry{
			ID:       "org.example:artifact:1.0.0",
			Checksum: "abcd1234567890",
			Type:     "jar",
		}

		pkgInfo := createPkgInfo("org.example:artifact", "1.0.0", provenanceEntry, true)

		assert.Equal(t, "org.example:artifact", pkgInfo.Name)
		assert.Equal(t, "1.0.0", pkgInfo.Version)
		assert.Equal(t, "pkg:maven/org.example/artifact@1.0.0?checksum=sha1:abcd1234567890", pkgInfo.PackageURL)
	})

	t.Run("creates PkgInfo with SHA1 checksum in PURL", func(t *testing.T) {
		provenanceEntry := &allDepEntry{
			ID:       "org.example:artifact:1.0.0",
			Checksum: "abcd1234567890",
			Type:     "jar",
		}

		pkgInfo := createPkgInfo("org.example:artifact", "1.0.0", provenanceEntry, true)

		assert.Equal(t, "pkg:maven/org.example/artifact@1.0.0?checksum=sha1:abcd1234567890", pkgInfo.PackageURL)
	})

	t.Run("creates PURL without checksum when checksum is empty", func(t *testing.T) {
		provenanceEntry := &allDepEntry{
			ID:   "org.example:artifact:1.0.0",
			Type: "jar",
		}

		pkgInfo := createPkgInfo("org.example:artifact", "1.0.0", provenanceEntry, true)

		assert.Equal(t, "pkg:maven/org.example/artifact@1.0.0", pkgInfo.PackageURL)
	})

	t.Run("skips PURL for non-standard dependency ID format", func(t *testing.T) {
		provenanceEntry := &allDepEntry{
			ID:       "invalid-id",
			Checksum: "abcd1234567890",
			Type:     "jar",
		}

		pkgInfo := createPkgInfo("invalid-id", "", provenanceEntry, true)

		assert.Empty(t, pkgInfo.PackageURL)
	})
}
