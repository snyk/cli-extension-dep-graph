package bun

import (
	"testing"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findResultByRoot returns the depGraphResult whose root package name equals rootName.
func findResultByRoot(t *testing.T, results []depGraphResult, rootName string) depGraphResult {
	t.Helper()

	for _, r := range results {
		if r.graph.GetRootPkg().Info.Name == rootName {
			return r
		}
	}

	t.Fatalf("no dep graph with root package %q", rootName)

	return depGraphResult{}
}

func TestBuildDepGraphs_Simple(t *testing.T) {
	// root → debug@4.4.3 → ms@2.1.3 (no workspaces)
	out := &whyOutput{
		Graph: reverseGraph{
			"debug@4.4.3": {},                  // root-direct (no versioned dependents)
			"ms@2.1.3":    {"debug@4.4.3": {}}, // debug depends on ms
		},
		ProdDeps: []string{"debug@4.4.3"},
	}

	results, err := buildDepGraphs("my-app", "1.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 1, "non-workspace project produces exactly one dep graph")

	r := results[0]
	assert.Equal(t, "package.json", r.pkgJSONRelPath)
	assert.Equal(t, "bun", r.graph.PkgManager.Name)
	assert.Equal(t, "my-app", r.graph.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", r.graph.GetRootPkg().Info.Version)

	assert.Contains(t, nodeDeps(r.graph, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(r.graph, "debug@4.4.3"), "ms@2.1.3", "debug → ms")
	assert.Empty(t, nodeDeps(r.graph, "ms@2.1.3"), "ms has no deps")
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

	results, err := buildDepGraphs("my-workspace", "1.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 2, "root graph + one per workspace package")

	// Identify root and workspace graphs by root package name.
	rootResult := findResultByRoot(t, results, "my-workspace")
	loggerResult := findResultByRoot(t, results, "@workspace/logger")

	// Verify target file paths.
	assert.Equal(t, "package.json", rootResult.pkgJSONRelPath)
	assert.Equal(t, "packages/logger/package.json", loggerResult.pkgJSONRelPath)

	// Root graph: workspace package is a leaf — its transitive deps are absent.
	assert.Contains(t, nodeDeps(rootResult.graph, "root-node"), "@workspace/logger@workspace:packages/logger", "root → logger")
	assert.Contains(t, nodeDeps(rootResult.graph, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(rootResult.graph, "debug@4.4.3"), "ms@2.1.3", "debug → ms in root graph")
	assert.Empty(t, nodeDeps(rootResult.graph, "@workspace/logger@workspace:packages/logger"),
		"logger is a leaf in the root graph — its subtree lives in its own dep graph")

	// Workspace logger graph: logger's subtree is fully walked.
	assert.Contains(t, nodeDeps(loggerResult.graph, "root-node"), "axios@1.14.0", "logger root → axios")
	assert.Contains(t, nodeDeps(loggerResult.graph, "axios@1.14.0"), "follow-redirects@1.15.9", "axios → follow-redirects")
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

	results, err := buildDepGraphs("root", "0.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 3, "root + wsA + wsB")

	rootResult := findResultByRoot(t, results, "root")
	wsAResult := findResultByRoot(t, results, "wsA")
	wsBResult := findResultByRoot(t, results, "wsB")

	// Verify target file paths.
	assert.Equal(t, "package.json", rootResult.pkgJSONRelPath)
	assert.Equal(t, "packages/a/package.json", wsAResult.pkgJSONRelPath)
	assert.Equal(t, "packages/b/package.json", wsBResult.pkgJSONRelPath)

	// Both workspace packages appear as leaves in the root graph.
	assert.Contains(t, nodeDeps(rootResult.graph, "root-node"), "wsA@workspace:packages/a")
	assert.Contains(t, nodeDeps(rootResult.graph, "root-node"), "wsB@workspace:packages/b")
	assert.Empty(t, nodeDeps(rootResult.graph, "wsA@workspace:packages/a"), "wsA is a leaf in root graph")
	assert.Empty(t, nodeDeps(rootResult.graph, "wsB@workspace:packages/b"), "wsB is a leaf in root graph")

	// In wsA's own graph, wsB appears as a leaf (cycle broken by stopAt).
	assert.Contains(t, nodeDeps(wsAResult.graph, "root-node"), "wsB@workspace:packages/b", "wsA root → wsB")
	assert.Empty(t, nodeDeps(wsAResult.graph, "wsB@workspace:packages/b"), "wsB is a leaf in wsA graph")

	// In wsB's own graph, wsA appears as a leaf (cycle broken by stopAt).
	assert.Contains(t, nodeDeps(wsBResult.graph, "root-node"), "wsA@workspace:packages/a", "wsB root → wsA")
	assert.Empty(t, nodeDeps(wsBResult.graph, "wsA@workspace:packages/a"), "wsA is a leaf in wsB graph")
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
	results, err := buildDepGraphs("root", "0.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "package.json", r.pkgJSONRelPath)
	assert.Contains(t, nodeDeps(r.graph, "root-node"), "pkg-a@1.0.0", "root → pkg-a")
	assert.Contains(t, nodeDeps(r.graph, "pkg-a@1.0.0"), "pkg-b@2.0.0", "pkg-a → pkg-b")
	assert.Contains(t, nodeDeps(r.graph, "pkg-b@2.0.0"), "pkg-a@1.0.0", "pkg-b → pkg-a (cycle edge present)")
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
