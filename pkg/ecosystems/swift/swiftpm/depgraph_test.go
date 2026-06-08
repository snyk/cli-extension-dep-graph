package swiftpm

import (
	"testing"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageNameFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/apple/swift-nio.git", "github.com/apple/swift-nio"},
		{"https://github.com/apple/swift-nio", "github.com/apple/swift-nio"},
		{"https://gitlab.com/group/proj.git", "gitlab.com/group/proj"},
		{"http://example.com/foo.git", "example.com/foo"},
		{"apple.swift-argument-parser", "github.com/apple/swift-argument-parser"},
		{"apple.foo-bar", "github.com/apple/foo-bar"},
		// Path deps and other unknown shapes pass through unchanged.
		{"/local/path/to/dep", "/local/path/to/dep"},
		{"some-bare-name", "some-bare-name"},
		// Identity format requires exactly one dot in scope.name shape — these don't match.
		{"too.many.dots", "too.many.dots"},
		{".leading-dot", ".leading-dot"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, packageNameFromURL(tt.url))
		})
	}
}

func TestBuildDepGraph_Simple(t *testing.T) {
	// root → grpc-swift@1.16.0 → swift-nio@2.54.0
	root := &depTreeNode{
		Name:    "my-app",
		URL:     "/local/path/my-app",
		Version: "unspecified",
		Dependencies: []*depTreeNode{
			{
				Name:    "grpc-swift",
				URL:     "https://github.com/grpc/grpc-swift.git",
				Version: "1.16.0",
				Dependencies: []*depTreeNode{
					{
						Name:    "swift-nio",
						URL:     "https://github.com/apple/swift-nio.git",
						Version: "2.54.0",
					},
				},
			},
		},
	}

	dg, err := buildDepGraph("my-app", root)
	require.NoError(t, err)
	require.NotNil(t, dg)

	assert.Equal(t, "swift", dg.PkgManager.Name)
	assert.Equal(t, "my-app", dg.GetRootPkg().Info.Name)
	assert.Equal(t, "unspecified", dg.GetRootPkg().Info.Version)

	grpcID := "github.com/grpc/grpc-swift@1.16.0"
	nioID := "github.com/apple/swift-nio@2.54.0"

	assert.Contains(t, nodeDeps(dg, "root-node"), grpcID, "root → grpc-swift")
	assert.Contains(t, nodeDeps(dg, grpcID), nioID, "grpc → nio")
	assert.Empty(t, nodeDeps(dg, nioID), "nio has no deps")
}

func TestBuildDepGraph_RootNameFallsBackToTreeName(t *testing.T) {
	// When rootName is empty, the JSON `name` field is used.
	root := &depTreeNode{
		Name:    "from-json",
		URL:     "/local",
		Version: "unspecified",
	}

	dg, err := buildDepGraph("", root)
	require.NoError(t, err)
	assert.Equal(t, "from-json", dg.GetRootPkg().Info.Name)
}

func TestBuildDepGraph_EmptyVersionDefaulted(t *testing.T) {
	// swift normally emits "unspecified" for unknown versions; defend against
	// a truly empty string by replacing it with defaultVersion so the
	// dep-graph builder doesn't reject the node.
	root := &depTreeNode{
		Name:    "root",
		URL:     "/local",
		Version: "",
		Dependencies: []*depTreeNode{
			{
				Name:    "missing-version-dep",
				URL:     "https://example.com/foo",
				Version: "",
			},
		},
	}

	dg, err := buildDepGraph("root", root)
	require.NoError(t, err)
	assert.Equal(t, defaultVersion, dg.GetRootPkg().Info.Version)
	assert.Contains(t, nodeDeps(dg, "root-node"), "example.com/foo@"+defaultVersion)
}

func TestBuildDepGraph_PreservesUnspecified(t *testing.T) {
	// "unspecified" comes from swift verbatim and is the conventional
	// version string for path: / branch: deps; preserve it for parity with
	// the legacy plugin.
	root := &depTreeNode{
		Name:    "root",
		URL:     "/local",
		Version: "unspecified",
		Dependencies: []*depTreeNode{
			{
				Name:    "local-dep",
				URL:     "/some/local/path",
				Version: "unspecified",
			},
		},
	}

	dg, err := buildDepGraph("root", root)
	require.NoError(t, err)
	assert.Equal(t, "unspecified", dg.GetRootPkg().Info.Version)
	assert.Contains(t, nodeDeps(dg, "root-node"), "/some/local/path@unspecified")
}

func TestBuildDepGraph_Diamond(t *testing.T) {
	// root → a@1, b@1; both depend on shared@1
	shared := &depTreeNode{
		Name:    "shared",
		URL:     "https://github.com/x/shared.git",
		Version: "1.0.0",
	}
	root := &depTreeNode{
		Name:    "root",
		URL:     "/local",
		Version: "unspecified",
		Dependencies: []*depTreeNode{
			{
				Name:         "a",
				URL:          "https://github.com/x/a.git",
				Version:      "1.0.0",
				Dependencies: []*depTreeNode{shared},
			},
			{
				Name:         "b",
				URL:          "https://github.com/x/b.git",
				Version:      "1.0.0",
				Dependencies: []*depTreeNode{shared},
			},
		},
	}

	dg, err := buildDepGraph("root", root)
	require.NoError(t, err)

	sharedID := "github.com/x/shared@1.0.0"
	assert.Contains(t, nodeDeps(dg, "github.com/x/a@1.0.0"), sharedID)
	assert.Contains(t, nodeDeps(dg, "github.com/x/b@1.0.0"), sharedID)

	// Shared node should appear exactly once in the pkg list.
	count := 0
	for _, p := range dg.Pkgs {
		if p.ID == sharedID {
			count++
		}
	}
	assert.Equal(t, 1, count, "shared dep deduplicated")
}

func TestBuildDepGraph_CycleTerminates(t *testing.T) {
	// a → b → a cycle: visited guard must break recursion.
	a := &depTreeNode{
		Name:    "a",
		URL:     "https://github.com/x/a.git",
		Version: "1.0.0",
	}
	b := &depTreeNode{
		Name:         "b",
		URL:          "https://github.com/x/b.git",
		Version:      "1.0.0",
		Dependencies: []*depTreeNode{a},
	}
	a.Dependencies = []*depTreeNode{b}

	root := &depTreeNode{
		Name:         "root",
		URL:          "/local",
		Version:      "unspecified",
		Dependencies: []*depTreeNode{a},
	}

	dg, err := buildDepGraph("root", root)
	require.NoError(t, err)

	aID := "github.com/x/a@1.0.0"
	bID := "github.com/x/b@1.0.0"
	assert.Contains(t, nodeDeps(dg, "root-node"), aID)
	assert.Contains(t, nodeDeps(dg, aID), bID)
	assert.Contains(t, nodeDeps(dg, bID), aID, "cycle edge present, recursion bounded")
}

func TestBuildDepGraph_RegistryIdentityNormalised(t *testing.T) {
	// Registry identities like "apple.swift-argument-parser" map to
	// github.com/<scope>/<name> for parity with the legacy plugin.
	root := &depTreeNode{
		Name:    "root",
		URL:     "/local",
		Version: "unspecified",
		Dependencies: []*depTreeNode{
			{
				Name:    "swift-argument-parser",
				URL:     "apple.swift-argument-parser",
				Version: "1.2.0",
			},
		},
	}

	dg, err := buildDepGraph("root", root)
	require.NoError(t, err)
	assert.Contains(t, nodeDeps(dg, "root-node"), "github.com/apple/swift-argument-parser@1.2.0")
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
