package npm

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

// dep is a builder shorthand for *listResponseDep.
func dep(version string, deps ...map[string]*listResponseDep) *listResponseDep {
	d := &listResponseDep{Version: version}
	if len(deps) > 0 {
		d.Dependencies = deps[0]
	}
	return d
}

// wsDep returns a workspace listResponseDep at version 1.0.0 with the given
// relative dir encoded via the "file:" Resolved field.
func wsDep(relDir string, deps ...map[string]*listResponseDep) *listResponseDep {
	d := dep("1.0.0", deps...)
	d.Resolved = "file:" + relDir
	return d
}

func TestBuildDepGraphs_Simple(t *testing.T) {
	// root → debug@4.4.3 → ms@2.1.3
	root := &listResponse{
		Name:    "my-app",
		Version: "1.0.0",
		Dependencies: map[string]*listResponseDep{
			"debug": dep("4.4.3", map[string]*listResponseDep{
				"ms": dep("2.1.3"),
			}),
		},
	}

	results, err := buildDepGraphs("my-app", "1.0.0", root, nil)
	require.NoError(t, err)
	require.Len(t, results, 1, "non-workspace project produces exactly one dep graph")

	r := results[0]
	assert.Equal(t, "package.json", r.pkgJSONRelPath)
	assert.Equal(t, "npm", r.graph.PkgManager.Name)
	assert.Equal(t, "my-app", r.graph.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", r.graph.GetRootPkg().Info.Version)

	assert.Contains(t, nodeDeps(r.graph, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(r.graph, "debug@4.4.3"), "ms@2.1.3", "debug → ms")
	assert.Empty(t, nodeDeps(r.graph, "ms@2.1.3"), "ms has no deps")
}

func TestBuildDepGraphs_Diamond(t *testing.T) {
	// root → a@1, b@1; both depend on shared@1
	root := &listResponse{
		Dependencies: map[string]*listResponseDep{
			"a": dep("1.0.0", map[string]*listResponseDep{
				"shared": dep("1.0.0"),
			}),
			"b": dep("1.0.0", map[string]*listResponseDep{
				"shared": dep("1.0.0"),
			}),
		},
	}

	results, err := buildDepGraphs("root", "0.0.0", root, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)

	dg := results[0].graph
	assert.Contains(t, nodeDeps(dg, "root-node"), "a@1.0.0")
	assert.Contains(t, nodeDeps(dg, "root-node"), "b@1.0.0")
	assert.Contains(t, nodeDeps(dg, "a@1.0.0"), "shared@1.0.0")
	assert.Contains(t, nodeDeps(dg, "b@1.0.0"), "shared@1.0.0")
}

func TestBuildDepGraphs_MultipleVersions(t *testing.T) {
	// Two unrelated copies of "lodash" at different versions in the tree.
	root := &listResponse{
		Dependencies: map[string]*listResponseDep{
			"lodash": dep("4.17.0"),
			"a": dep("1.0.0", map[string]*listResponseDep{
				"lodash": dep("3.10.0"),
			}),
		},
	}

	results, err := buildDepGraphs("root", "0.0.0", root, nil)
	require.NoError(t, err)
	dg := results[0].graph

	ids := make(map[string]bool)
	for _, p := range dg.Pkgs {
		ids[p.ID] = true
	}
	assert.True(t, ids["lodash@4.17.0"], "first version present")
	assert.True(t, ids["lodash@3.10.0"], "second version present")
}

func TestBuildDepGraphs_WithWorkspaces(t *testing.T) {
	// Root direct deps: @workspace/logger (workspace), debug
	// Logger's transitive: axios → follow-redirects
	// debug's transitive: ms
	root := &listResponse{
		Dependencies: map[string]*listResponseDep{
			"@workspace/logger": wsDep("packages/logger", map[string]*listResponseDep{
				"axios": dep("1.14.0", map[string]*listResponseDep{
					"follow-redirects": dep("1.15.9"),
				}),
			}),
			"debug": dep("4.4.3", map[string]*listResponseDep{
				"ms": dep("2.1.3"),
			}),
		},
	}

	workspacePaths := map[string]string{
		"@workspace/logger": "packages/logger",
	}
	results, err := buildDepGraphs("my-workspace", "1.0.0", root, workspacePaths)
	require.NoError(t, err)
	require.Len(t, results, 2, "root graph + one per workspace package")

	rootResult := findResultByRoot(t, results, "my-workspace")
	loggerResult := findResultByRoot(t, results, "@workspace/logger")

	assert.Equal(t, "package.json", rootResult.pkgJSONRelPath)
	assert.Equal(t, "packages/logger/package.json", loggerResult.pkgJSONRelPath)

	// Root graph: workspace package is a leaf — its transitive deps are absent.
	loggerID := "@workspace/logger@file:packages/logger"
	assert.Contains(t, nodeDeps(rootResult.graph, "root-node"), loggerID, "root → logger")
	assert.Contains(t, nodeDeps(rootResult.graph, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(rootResult.graph, "debug@4.4.3"), "ms@2.1.3", "debug → ms in root graph")
	assert.Empty(t, nodeDeps(rootResult.graph, loggerID),
		"logger is a leaf in the root graph")

	// Workspace logger graph: logger's subtree is fully walked.
	assert.Contains(t, nodeDeps(loggerResult.graph, "root-node"), "axios@1.14.0", "logger root → axios")
	assert.Contains(t, nodeDeps(loggerResult.graph, "axios@1.14.0"), "follow-redirects@1.15.9", "axios → follow-redirects")
}

func TestBuildDepGraphs_CrossWorkspaceCycleTerminates(t *testing.T) {
	// wsA depends on wsB which depends on wsA. Must not infinite-loop.
	root := &listResponse{
		Dependencies: map[string]*listResponseDep{
			"wsA": wsDep("packages/a", map[string]*listResponseDep{
				"wsB": wsDep("packages/b"),
			}),
			"wsB": wsDep("packages/b", map[string]*listResponseDep{
				"wsA": wsDep("packages/a"),
			}),
		},
	}

	workspacePaths := map[string]string{
		"wsA": "packages/a",
		"wsB": "packages/b",
	}
	results, err := buildDepGraphs("root", "0.0.0", root, workspacePaths)
	require.NoError(t, err)
	require.Len(t, results, 3, "root + wsA + wsB")

	rootResult := findResultByRoot(t, results, "root")
	wsAID := "wsA@file:packages/a"
	wsBID := "wsB@file:packages/b"
	assert.Empty(t, nodeDeps(rootResult.graph, wsAID), "wsA is a leaf in root")
	assert.Empty(t, nodeDeps(rootResult.graph, wsBID), "wsB is a leaf in root")
}

func TestBuildDepGraphs_HandlesPackageLevelCycle(t *testing.T) {
	// pkg-a → pkg-b → pkg-a (cycle inside the listResponse). collectAdjacency
	// breaks the cycle via its visited set, and addNode breaks it again via
	// its own visited set during graph construction.
	cyclicA := &listResponseDep{Version: "1.0.0"}
	cyclicB := &listResponseDep{
		Version: "2.0.0",
		Dependencies: map[string]*listResponseDep{
			"pkg-a": cyclicA,
		},
	}
	cyclicA.Dependencies = map[string]*listResponseDep{"pkg-b": cyclicB}

	root := &listResponse{
		Dependencies: map[string]*listResponseDep{"pkg-a": cyclicA},
	}

	results, err := buildDepGraphs("root", "0.0.0", root, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)

	dg := results[0].graph
	assert.Contains(t, nodeDeps(dg, "root-node"), "pkg-a@1.0.0")
	assert.Contains(t, nodeDeps(dg, "pkg-a@1.0.0"), "pkg-b@2.0.0")
	assert.Contains(t, nodeDeps(dg, "pkg-b@2.0.0"), "pkg-a@1.0.0", "cycle edge present")
}

func TestSplitPkgID(t *testing.T) {
	tests := []struct {
		id          string
		wantName    string
		wantVersion string
	}{
		{"ms@2.0.0", "ms", "2.0.0"},
		{"@types/node@25.5.2", "@types/node", "25.5.2"},
		{"@workspace/logger@file:packages/logger", "@workspace/logger", "file:packages/logger"},
		{"no-at-sign", "no-at-sign", ""},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			name, version := splitPkgID(tt.id)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
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
