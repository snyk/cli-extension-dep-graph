package cargo

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// rootNodeID is the node ID the dep-graph builder gives the root package.
const rootNodeID = "root-node"

func TestBuildDepGraph(t *testing.T) {
	tests := []struct {
		name     string
		out      *treeOutput
		wantRoot string
		// wantNodes is the node order; wantEdges maps each node to its ordered deps.
		wantNodes []string
		wantEdges map[string][]string
	}{
		{
			name: "root with no deps",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0": {},
				},
			},
			wantRoot:  "my-app",
			wantNodes: []string{rootNodeID},
			wantEdges: map[string][]string{rootNodeID: {}},
		},
		{
			name: "linear chain",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0":         {"serde@1.0.193"},
					"serde@1.0.193":        {"serde_derive@1.0.193"},
					"serde_derive@1.0.193": {},
				},
			},
			wantRoot:  "my-app",
			wantNodes: []string{rootNodeID, "serde@1.0.193", "serde_derive@1.0.193"},
			wantEdges: map[string][]string{
				rootNodeID:             {"serde@1.0.193"},
				"serde@1.0.193":        {"serde_derive@1.0.193"},
				"serde_derive@1.0.193": {},
			},
		},
		{
			name: "diamond dependency (same crate reached by two paths)",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0": {"a@1.0.0", "b@1.0.0"},
					"a@1.0.0":      {"shared@1.0.0"},
					"b@1.0.0":      {"shared@1.0.0"},
					"shared@1.0.0": {},
				},
			},
			wantRoot:  "my-app",
			wantNodes: []string{rootNodeID, "a@1.0.0", "shared@1.0.0", "b@1.0.0"},
			wantEdges: map[string][]string{
				rootNodeID:     {"a@1.0.0", "b@1.0.0"},
				"a@1.0.0":      {"shared@1.0.0"},
				"b@1.0.0":      {"shared@1.0.0"},
				"shared@1.0.0": {},
			},
		},
		{
			name: "cycle does not infinite-loop",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0": {"foo@1.0.0"},
					"foo@1.0.0":    {"bar@1.0.0"},
					"bar@1.0.0":    {"foo@1.0.0"},
				},
			},
			wantRoot:  "my-app",
			wantNodes: []string{rootNodeID, "foo@1.0.0", "bar@1.0.0"},
			wantEdges: map[string][]string{
				rootNodeID:  {"foo@1.0.0"},
				"foo@1.0.0": {"bar@1.0.0"},
				"bar@1.0.0": {"foo@1.0.0"},
			},
		},
		{
			name: "multiple versions of the same crate coexist as distinct nodes",
			out: &treeOutput{
				RootID: "my-app@0.1.0",
				Graph: forwardGraph{
					"my-app@0.1.0":    {"rand@0.8.5", "rand_core@0.7.0"},
					"rand@0.8.5":      {"rand_core@0.6.4"},
					"rand_core@0.6.4": {},
					"rand_core@0.7.0": {},
				},
			},
			wantRoot:  "my-app",
			wantNodes: []string{rootNodeID, "rand@0.8.5", "rand_core@0.6.4", "rand_core@0.7.0"},
			wantEdges: map[string][]string{
				rootNodeID:        {"rand@0.8.5", "rand_core@0.7.0"},
				"rand@0.8.5":      {"rand_core@0.6.4"},
				"rand_core@0.6.4": {},
				"rand_core@0.7.0": {},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dg, err := buildDepGraph(tt.out, nil)
			require.NoError(t, err)

			assert.Equal(t, tt.wantRoot, dg.GetRootPkg().Info.Name)
			assert.Equal(t, "cargo", dg.PkgManager.Name)

			gotNodes, gotEdges := nodesAndEdges(dg)
			assert.Equal(t, tt.wantNodes, gotNodes)
			assert.Equal(t, tt.wantEdges, gotEdges)
		})
	}
}

func TestBuildDepGraph_StopAtWorkspaceMembers(t *testing.T) {
	// Workspace with two members "a" and "b". "a" depends on "b" (which has
	// its own deps). When we build a's dep graph with b in stopAt, b appears
	// as a leaf — its subtree should NOT be expanded inside a's graph.
	out := &treeOutput{
		RootID: "a@0.1.0",
		Graph: forwardGraph{
			"a@0.1.0":     {"b@0.1.0", "serde@1.0.0"},
			"b@0.1.0":     {"tokio@1.0.0"},
			"serde@1.0.0": {},
			"tokio@1.0.0": {},
		},
	}

	stopAt := map[string]struct{}{"b@0.1.0": {}}

	dg, err := buildDepGraph(out, stopAt)
	require.NoError(t, err)

	gotNodes, gotEdges := nodesAndEdges(dg)

	// b is a leaf of a's graph; tokio (b's transitive dep) belongs to b's graph only.
	assert.Equal(t, []string{rootNodeID, "b@0.1.0", "serde@1.0.0"}, gotNodes)
	assert.Equal(t, map[string][]string{
		rootNodeID:    {"b@0.1.0", "serde@1.0.0"},
		"b@0.1.0":     {},
		"serde@1.0.0": {},
	}, gotEdges)
}

func TestBuildDepGraph_PreservesCargoTreeOrder(t *testing.T) {
	// Siblings are deliberately not alphabetical, so only following the
	// input order passes.
	const tree = `0my-app v0.1.0
1zeta v1.0.0
2shared v1.0.0
1mu v1.0.0
2shared v1.0.0
1kappa v1.0.0
1beta v1.0.0
1omega v1.0.0
1alpha v1.0.0
1theta v1.0.0
1iota v1.0.0
1gamma v1.0.0
`

	wantNodes := []string{
		rootNodeID, "zeta@1.0.0", "shared@1.0.0", "mu@1.0.0", "kappa@1.0.0", "beta@1.0.0",
		"omega@1.0.0", "alpha@1.0.0", "theta@1.0.0", "iota@1.0.0", "gamma@1.0.0",
	}
	wantRootDeps := []string{
		"zeta@1.0.0", "mu@1.0.0", "kappa@1.0.0", "beta@1.0.0", "omega@1.0.0",
		"alpha@1.0.0", "theta@1.0.0", "iota@1.0.0", "gamma@1.0.0",
	}

	var first []byte

	for i := range 50 {
		out, err := parseTree(context.Background(), nil, strings.NewReader(tree))
		require.NoError(t, err)

		dg, err := buildDepGraph(out, nil)
		require.NoError(t, err)

		gotNodes, gotEdges := nodesAndEdges(dg)
		require.Equal(t, wantNodes, gotNodes, "run %d", i)
		require.Equal(t, wantRootDeps, gotEdges[rootNodeID], "run %d", i)

		data, err := json.Marshal(dg)
		require.NoError(t, err)

		if first == nil {
			first = data
		}

		require.JSONEq(t, string(first), string(data), "run %d differs from run 0", i)
	}
}

// nodesAndEdges returns the graph's node IDs in output order and each node's
// dep IDs in output order.
func nodesAndEdges(dg *godepgraph.DepGraph) ([]string, map[string][]string) {
	nodes := make([]string, 0, len(dg.Graph.Nodes))
	edges := make(map[string][]string, len(dg.Graph.Nodes))

	for _, n := range dg.Graph.Nodes {
		nodes = append(nodes, n.NodeID)
		edges[n.NodeID] = make([]string, 0, len(n.Deps))

		for _, d := range n.Deps {
			edges[n.NodeID] = append(edges[n.NodeID], d.NodeID)
		}
	}

	return nodes, edges
}
