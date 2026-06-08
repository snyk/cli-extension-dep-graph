package yarn

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

// nodeDeps returns the resolved package IDs reachable from the named node.
func nodeDeps(dg *godepgraph.DepGraph, nodeID string) []string {
	for _, n := range dg.Graph.Nodes {
		if n.NodeID != nodeID {
			continue
		}
		ids := make([]string, 0, len(n.Deps))
		for _, d := range n.Deps {
			ids = append(ids, d.NodeID)
		}
		return ids
	}
	return nil
}

func TestBuildDepGraphs_Simple(t *testing.T) {
	// root → accepts@1.3.7 → mime-types@2.1.31 → mime-db@1.48.0
	//                     → negotiator@0.6.2
	out := &parsedOutput{
		Graph: forwardGraph{
			"accepts@npm:1.3.7":     {"mime-types@npm:2.1.31": {}, "negotiator@npm:0.6.2": {}},
			"mime-types@npm:2.1.31": {"mime-db@npm:1.48.0": {}},
			"mime-db@npm:1.48.0":    {},
			"negotiator@npm:0.6.2":  {},
		},
		ProdDeps:   []string{"accepts@npm:1.3.7"},
		Workspaces: map[string]workspaceInfo{},
	}

	results, err := buildDepGraphs("my-app", "1.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "package.json", r.pkgJSONRelPath)
	assert.Equal(t, "yarn", r.graph.PkgManager.Name)
	assert.Equal(t, "my-app", r.graph.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", r.graph.GetRootPkg().Info.Version)

	assert.Contains(t, nodeDeps(r.graph, "root-node"), "accepts@npm:1.3.7")
	assert.Contains(t, nodeDeps(r.graph, "accepts@npm:1.3.7"), "mime-types@npm:2.1.31")
	assert.Contains(t, nodeDeps(r.graph, "mime-types@npm:2.1.31"), "mime-db@npm:1.48.0")
}

// TestBuildDepGraphs_PkgInfoStripsNpmProtocol verifies that npm: prefixes
// are stripped from PkgInfo.Version (and therefore the derived Pkg ID) while
// graph node IDs keep the raw locator. This is what produces sane
// "debug@4.3.1" entries in vuln reports despite Berry's raw "debug@npm:4.3.1".
func TestBuildDepGraphs_PkgInfoStripsNpmProtocol(t *testing.T) {
	out := &parsedOutput{
		Graph: forwardGraph{
			"debug@npm:4.3.1": {},
		},
		ProdDeps:   []string{"debug@npm:4.3.1"},
		Workspaces: map[string]workspaceInfo{},
	}
	results, err := buildDepGraphs("root", "0.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 1)

	dg := results[0].graph

	// Pkg ID is derived from PkgInfo (name@strippedVersion), so we expect
	// "debug@4.3.1" — not the raw "debug@npm:4.3.1" used as the node ID.
	var debugPkg *godepgraph.Pkg
	for i := range dg.Pkgs {
		if dg.Pkgs[i].ID == "debug@4.3.1" {
			debugPkg = &dg.Pkgs[i]
			break
		}
	}
	require.NotNil(t, debugPkg, "expected pkg with derived id debug@4.3.1")
	assert.Equal(t, "debug", debugPkg.Info.Name)
	assert.Equal(t, "4.3.1", debugPkg.Info.Version, "npm: prefix stripped from PkgInfo.Version")

	// The raw locator is still the node ID — that's what's reachable from root.
	assert.Contains(t, nodeDeps(dg, "root-node"), "debug@npm:4.3.1")
}

func TestBuildDepGraphs_WithWorkspaces(t *testing.T) {
	// Root deps: @my/logger (workspace), debug@npm:4.4.3
	// @my/logger has: chalk@npm:5
	// debug has: ms@2.1.3
	out := &parsedOutput{
		Graph: forwardGraph{
			"@my/logger@workspace:packages/logger": {"chalk@npm:5.0.0": {}},
			"debug@npm:4.4.3":                       {"ms@npm:2.1.3": {}},
			"chalk@npm:5.0.0":                       {},
			"ms@npm:2.1.3":                          {},
		},
		ProdDeps: []string{"@my/logger@workspace:packages/logger", "debug@npm:4.4.3"},
		Workspaces: map[string]workspaceInfo{
			"@my/logger@workspace:packages/logger": {
				Dir: "packages/logger", Name: "@my/logger", Version: "0.1.0",
			},
		},
	}

	results, err := buildDepGraphs("my-workspace", "1.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 2, "root + one workspace member")

	root := findResultByRoot(t, results, "my-workspace")
	logger := findResultByRoot(t, results, "@my/logger")

	assert.Equal(t, "package.json", root.pkgJSONRelPath)
	assert.Equal(t, "packages/logger/package.json", logger.pkgJSONRelPath)

	// Root graph: workspace member is a leaf — its subtree (chalk) does NOT appear.
	assert.Contains(t, nodeDeps(root.graph, "root-node"),
		"@my/logger@workspace:packages/logger")
	assert.Empty(t, nodeDeps(root.graph, "@my/logger@workspace:packages/logger"),
		"workspace member is a leaf in the root graph")
	assert.Contains(t, nodeDeps(root.graph, "debug@npm:4.4.3"), "ms@npm:2.1.3")

	// Workspace's own graph: its subtree (chalk) is fully walked.
	assert.Contains(t, nodeDeps(logger.graph, "root-node"), "chalk@npm:5.0.0")
}

func TestBuildDepGraphs_WorkspaceCycle(t *testing.T) {
	// wsA → wsB → wsA (cross-workspace cycle). Must not infinite-loop, and each
	// workspace must appear as a leaf in the other's graph (stopAt breaks the cycle).
	out := &parsedOutput{
		Graph: forwardGraph{
			"wsA@workspace:packages/a": {"wsB@workspace:packages/b": {}},
			"wsB@workspace:packages/b": {"wsA@workspace:packages/a": {}},
		},
		ProdDeps: []string{"wsA@workspace:packages/a", "wsB@workspace:packages/b"},
		Workspaces: map[string]workspaceInfo{
			"wsA@workspace:packages/a": {Dir: "packages/a", Name: "wsA", Version: "0.0.0"},
			"wsB@workspace:packages/b": {Dir: "packages/b", Name: "wsB", Version: "0.0.0"},
		},
	}

	results, err := buildDepGraphs("root", "0.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 3, "root + wsA + wsB")

	wsAResult := findResultByRoot(t, results, "wsA")
	wsBResult := findResultByRoot(t, results, "wsB")

	// wsA's graph: wsB appears as a leaf — cycle broken.
	assert.Contains(t, nodeDeps(wsAResult.graph, "root-node"), "wsB@workspace:packages/b")
	assert.Empty(t, nodeDeps(wsAResult.graph, "wsB@workspace:packages/b"))

	// wsB's graph: wsA appears as a leaf — cycle broken.
	assert.Contains(t, nodeDeps(wsBResult.graph, "root-node"), "wsA@workspace:packages/a")
	assert.Empty(t, nodeDeps(wsBResult.graph, "wsA@workspace:packages/a"))
}

func TestBuildDepGraphs_HandlesPackageCycle(t *testing.T) {
	// a → b → a (package-level cycle). Must not infinite-loop.
	out := &parsedOutput{
		Graph: forwardGraph{
			"a@npm:1.0.0": {"b@npm:2.0.0": {}},
			"b@npm:2.0.0": {"a@npm:1.0.0": {}},
		},
		ProdDeps:   []string{"a@npm:1.0.0"},
		Workspaces: map[string]workspaceInfo{},
	}

	results, err := buildDepGraphs("root", "0.0.0", out)
	require.NoError(t, err)
	require.Len(t, results, 1)

	dg := results[0].graph
	assert.Contains(t, nodeDeps(dg, "root-node"), "a@npm:1.0.0")
	assert.Contains(t, nodeDeps(dg, "a@npm:1.0.0"), "b@npm:2.0.0")
	assert.Contains(t, nodeDeps(dg, "b@npm:2.0.0"), "a@npm:1.0.0",
		"visited set prevents re-walk; the back-edge is still recorded")
}

func TestSplitPkgID_StripsNpmOnly(t *testing.T) {
	// Sanity: protocols other than npm: are preserved verbatim because their
	// payload encodes meaningful information.
	_, ver := splitPkgID("pkg@workspace:packages/x")
	assert.Equal(t, "workspace:packages/x", ver)

	_, ver = splitPkgID("pkg@file:./local")
	assert.Equal(t, "file:./local", ver)

	_, ver = splitPkgID("pkg@patch:tgz#diff")
	assert.Equal(t, "patch:tgz#diff", ver)
}
