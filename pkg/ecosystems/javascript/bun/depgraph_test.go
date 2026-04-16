package bun

import (
	"testing"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDepGraphs_Simple(t *testing.T) {
	// root → debug@4.4.3 → ms@2.1.3 (no workspaces)
	out := &whyOutput{
		Graph: reverseGraph{
			"debug@4.4.3": {},                  // root-direct (no versioned dependents)
			"ms@2.1.3":    {"debug@4.4.3": {}}, // debug depends on ms
		},
		ProdDeps: []string{"debug@4.4.3"},
	}

	graphs, err := buildDepGraphs("my-app", "1.0.0", out)
	require.NoError(t, err)
	require.Len(t, graphs, 1, "non-workspace project produces exactly one dep graph")

	dg := graphs[0]
	assert.Equal(t, "bun", dg.PkgManager.Name)
	assert.Equal(t, "my-app", dg.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", dg.GetRootPkg().Info.Version)

	assert.Contains(t, nodeDeps(dg, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(dg, "debug@4.4.3"), "ms@2.1.3", "debug → ms")
	assert.Empty(t, nodeDeps(dg, "ms@2.1.3"), "ms has no deps")
}

func TestBuildDepGraphs_WithWorkspaces(t *testing.T) {
	// Root project direct deps: @workspace/logger, debug
	// @workspace/logger has transitive: axios → follow-redirects
	// debug has transitive: ms
	out := &whyOutput{
		Graph: reverseGraph{
			"@workspace/logger@workspace:packages/logger": {},
			"debug@4.4.3":             {},
			"axios@1.14.0":            {"@workspace/logger@workspace:packages/logger": {}},
			"follow-redirects@1.15.9": {"axios@1.14.0": {}},
			"ms@2.1.3":                {"debug@4.4.3": {}},
		},
		ProdDeps: []string{
			"@workspace/logger@workspace:packages/logger",
			"debug@4.4.3",
		},
	}

	graphs, err := buildDepGraphs("my-workspace", "1.0.0", out)
	require.NoError(t, err)
	require.Len(t, graphs, 2, "root graph + one per workspace package")

	// Identify root and workspace graphs by root package name.
	rootGraph := findGraphByRoot(t, graphs, "my-workspace")
	loggerGraph := findGraphByRoot(t, graphs, "@workspace/logger")

	// Root graph: workspace package is a leaf — its transitive deps are absent.
	assert.Contains(t, nodeDeps(rootGraph, "root-node"), "@workspace/logger@workspace:packages/logger", "root → logger")
	assert.Contains(t, nodeDeps(rootGraph, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(rootGraph, "debug@4.4.3"), "ms@2.1.3", "debug → ms in root graph")
	assert.Empty(t, nodeDeps(rootGraph, "@workspace/logger@workspace:packages/logger"),
		"logger is a leaf in the root graph — its subtree lives in its own dep graph")

	// Workspace logger graph: logger's subtree is fully walked.
	assert.Contains(t, nodeDeps(loggerGraph, "root-node"), "axios@1.14.0", "logger root → axios")
	assert.Contains(t, nodeDeps(loggerGraph, "axios@1.14.0"), "follow-redirects@1.15.9", "axios → follow-redirects")
}

func TestBuildDepGraphs_WorkspaceCycle(t *testing.T) {
	// wsA → wsB → wsA (cross-workspace cycle). Must not infinite-loop.
	out := &whyOutput{
		Graph: reverseGraph{
			"wsA@workspace:packages/a": {"wsB@workspace:packages/b": {}},
			"wsB@workspace:packages/b": {"wsA@workspace:packages/a": {}},
		},
		ProdDeps: []string{"wsA@workspace:packages/a", "wsB@workspace:packages/b"},
	}

	graphs, err := buildDepGraphs("root", "0.0.0", out)
	require.NoError(t, err)
	require.Len(t, graphs, 3, "root + wsA + wsB")

	rootGraph := findGraphByRoot(t, graphs, "root")
	wsAGraph := findGraphByRoot(t, graphs, "wsA")
	wsBGraph := findGraphByRoot(t, graphs, "wsB")

	// Both workspace packages appear as leaves in the root graph.
	assert.Contains(t, nodeDeps(rootGraph, "root-node"), "wsA@workspace:packages/a")
	assert.Contains(t, nodeDeps(rootGraph, "root-node"), "wsB@workspace:packages/b")
	assert.Empty(t, nodeDeps(rootGraph, "wsA@workspace:packages/a"), "wsA is a leaf in root graph")
	assert.Empty(t, nodeDeps(rootGraph, "wsB@workspace:packages/b"), "wsB is a leaf in root graph")

	// In wsA's own graph, wsB appears as a leaf (cycle broken by stopAt).
	assert.Contains(t, nodeDeps(wsAGraph, "root-node"), "wsB@workspace:packages/b", "wsA root → wsB")
	assert.Empty(t, nodeDeps(wsAGraph, "wsB@workspace:packages/b"), "wsB is a leaf in wsA graph")

	// In wsB's own graph, wsA appears as a leaf (cycle broken by stopAt).
	assert.Contains(t, nodeDeps(wsBGraph, "root-node"), "wsA@workspace:packages/a", "wsB root → wsA")
	assert.Empty(t, nodeDeps(wsBGraph, "wsA@workspace:packages/a"), "wsA is a leaf in wsB graph")
}

func TestBuildDepGraphs_HandlesCircularDeps(t *testing.T) {
	// pkg-a → pkg-b → pkg-a (cycle)
	out := &whyOutput{
		Graph: reverseGraph{
			"pkg-a@1.0.0": {"pkg-b@2.0.0": {}},
			"pkg-b@2.0.0": {"pkg-a@1.0.0": {}},
		},
		ProdDeps: []string{"pkg-a@1.0.0"},
	}

	// Must not infinite-loop.
	graphs, err := buildDepGraphs("root", "0.0.0", out)
	require.NoError(t, err)
	require.Len(t, graphs, 1)

	dg := graphs[0]
	assert.Contains(t, nodeDeps(dg, "root-node"), "pkg-a@1.0.0", "root → pkg-a")
	assert.Contains(t, nodeDeps(dg, "pkg-a@1.0.0"), "pkg-b@2.0.0", "pkg-a → pkg-b")
	assert.Contains(t, nodeDeps(dg, "pkg-b@2.0.0"), "pkg-a@1.0.0", "pkg-b → pkg-a (cycle edge present)")
}

// findGraphByRoot returns the dep graph whose root package name equals rootName.
func findGraphByRoot(t *testing.T, graphs []*godepgraph.DepGraph, rootName string) *godepgraph.DepGraph {
	t.Helper()

	for _, g := range graphs {
		if g.GetRootPkg().Info.Name == rootName {
			return g
		}
	}

	t.Fatalf("no dep graph with root package %q", rootName)

	return nil
}

// nodeDeps returns the NodeIDs of nodeID's direct dependencies in dg.
func nodeDeps(dg *godepgraph.DepGraph, nodeID string) []string {
	for _, n := range dg.Graph.Nodes {
		if n.NodeID == nodeID {
			ids := make([]string, len(n.Deps))
			for i, d := range n.Deps {
				ids[i] = d.NodeID
			}
			return ids
		}
	}
	return nil
}
