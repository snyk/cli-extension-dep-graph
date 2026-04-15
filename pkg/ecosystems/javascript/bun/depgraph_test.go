package bun

import (
	"testing"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDepGraph_Simple(t *testing.T) {
	// root → debug@4.4.3 → ms@2.1.3
	out := &whyOutput{
		Graph: reverseGraph{
			"debug@4.4.3": {},                  // root-direct (no versioned dependents)
			"ms@2.1.3":    {"debug@4.4.3": {}}, // debug depends on ms
		},
		ProdDeps: []string{"debug@4.4.3"},
	}

	dg, err := buildDepGraph("my-app", "1.0.0", out)
	require.NoError(t, err)
	require.NotNil(t, dg)

	assert.Equal(t, "bun", dg.PkgManager.Name)
	assert.Equal(t, "my-app", dg.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", dg.GetRootPkg().Info.Version)

	pkgIDs := make(map[string]bool)
	for _, p := range dg.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])

	assert.Contains(t, nodeDeps(dg, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(dg, "debug@4.4.3"), "ms@2.1.3", "debug → ms")
	assert.Empty(t, nodeDeps(dg, "ms@2.1.3"), "ms has no deps")
}

func TestBuildDepGraph_WorkspaceMegaGraph(t *testing.T) {
	// root → @workspace/logger → axios → follow-redirects
	// root → debug → ms
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

	dg, err := buildDepGraph("my-workspace", "1.0.0", out)
	require.NoError(t, err)
	require.NotNil(t, dg)

	pkgIDs := make(map[string]bool)
	for _, p := range dg.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["@workspace/logger@workspace:packages/logger"])
	assert.True(t, pkgIDs["axios@1.14.0"])
	assert.True(t, pkgIDs["follow-redirects@1.15.9"])
	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])

	assert.Contains(t, nodeDeps(dg, "root-node"), "@workspace/logger@workspace:packages/logger", "root → logger")
	assert.Contains(t, nodeDeps(dg, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(dg, "@workspace/logger@workspace:packages/logger"), "axios@1.14.0", "logger → axios")
	assert.Contains(t, nodeDeps(dg, "axios@1.14.0"), "follow-redirects@1.15.9", "axios → follow-redirects")
	assert.Contains(t, nodeDeps(dg, "debug@4.4.3"), "ms@2.1.3", "debug → ms")
}

func TestBuildDepGraph_HandlesCircularDeps(t *testing.T) {
	// pkg-a → pkg-b → pkg-a (cycle).
	// In reverseGraph: pkg-b depends on pkg-a → rev["pkg-a"] = {"pkg-b@2.0.0"}
	//                  pkg-a depends on pkg-b → rev["pkg-b"] = {"pkg-a@1.0.0"}
	out := &whyOutput{
		Graph: reverseGraph{
			"pkg-a@1.0.0": {"pkg-b@2.0.0": {}},
			"pkg-b@2.0.0": {"pkg-a@1.0.0": {}},
		},
		ProdDeps: []string{"pkg-a@1.0.0"},
	}

	// Must not infinite-loop.
	dg, err := buildDepGraph("root", "0.0.0", out)
	require.NoError(t, err)
	require.NotNil(t, dg)

	assert.Contains(t, nodeDeps(dg, "root-node"), "pkg-a@1.0.0", "root → pkg-a")
	assert.Contains(t, nodeDeps(dg, "pkg-a@1.0.0"), "pkg-b@2.0.0", "pkg-a → pkg-b")
	assert.Contains(t, nodeDeps(dg, "pkg-b@2.0.0"), "pkg-a@1.0.0", "pkg-b → pkg-a (cycle edge present)")
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
