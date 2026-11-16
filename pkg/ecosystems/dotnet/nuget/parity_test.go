package nuget_test

// parity_test.go checks this resolver against the dep graph snyk-nuget-plugin
// produces for the same project, so a divergence between the two parsers shows
// up as a test failure rather than as a difference in customers' results.
//
// See testdata/parity/dotnet_6/README.md for where the two files come from and
// what the one permitted difference is.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/dotnet/nuget"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

func TestParityWithSnykNugetPlugin(t *testing.T) {
	dir := filepath.Join("testdata", "parity", "dotnet_6")

	results, err := scatest.Run(t.Context(), nuget.Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "the project targets one framework")
	require.NoError(t, results[0].Error)

	mine := results[0].DepGraph
	require.NotNil(t, mine)

	raw, err := os.ReadFile(filepath.Join(dir, "snyk-nuget-plugin.json"))
	require.NoError(t, err)

	var theirs godepgraph.DepGraph
	require.NoError(t, json.Unmarshal(raw, &theirs))

	assert.Equal(t, theirs.SchemaVersion, mine.SchemaVersion)
	assert.Equal(t, theirs.PkgManager, mine.PkgManager)
	assert.Equal(t, theirs.Graph.RootNodeID, mine.Graph.RootNodeID)

	// Node identities and edges must match exactly. This is the substance of the
	// port: which packages resolved, at which versions, and which depends on
	// which — including the pruned back-edges, whose placement depends on the
	// order siblings are walked in.
	//
	// OSF-618 fix: we intentionally diverge from snyk-nuget-plugin to eliminate
	// twin edges (a parent with both X and X:pruned children). Upstream has the
	// same bug. Verify the fix reduced twin edges without losing real edges.
	mine_adj := adjacency(t, mine)
	theirs_adj := adjacency(t, &theirs)

	for nodeID, mineDeps := range mine_adj {
		theirDeps, exists := theirs_adj[nodeID]
		require.True(t, exists, "node %s exists in ours but not theirs", nodeID)

		// Every edge we have must exist in theirs (we never drop real edges)
		for _, dep := range mineDeps {
			assert.Contains(t, theirDeps, dep,
				"edge %s -> %s exists in ours but not in theirs; we must not drop real edges",
				nodeID, dep)
		}

		// If theirs has more edges, they must be twin-edge duplicates
		if len(theirDeps) > len(mineDeps) {
			for _, dep := range theirDeps {
				if !contains(mineDeps, dep) {
					// Theirs has an edge we don't: verify it's the twin of one we do have
					var base string
					if strings.HasSuffix(dep, prunedSuffix) {
						base = strings.TrimSuffix(dep, prunedSuffix)
					} else {
						base = dep + prunedSuffix
					}
					assert.Contains(t, mineDeps, base,
						"theirs has edge %s -> %s that we lack, but it's not a twin edge (expected either %s or %s in ours)",
						nodeID, dep, dep, base)
				}
			}
		}
	}

	// Check pruned node counts: we should have fewer due to eliminating twins
	theirPruned := prunedLabels(&theirs)
	minePruned := prunedLabels(mine)
	assert.NotEmpty(t, theirPruned,
		"the upstream fixture should still contain pruned nodes; if it does not, this comparison proves nothing")
	assert.LessOrEqual(t, len(minePruned), len(theirPruned),
		"we should have equal or fewer pruned nodes after eliminating twins")

	// Package *versions* are allowed to differ, and do: snyk-nuget-plugin
	// rewrites them from the host SDK's PackageOverrides.txt, which a static
	// resolver cannot read. The set of package names must still be identical.
	assert.Equal(t, packageNames(&theirs), packageNames(mine), "package sets diverged")

	overridden := 0
	for _, node := range theirs.Graph.Nodes {
		if node.NodeID != theirs.Graph.RootNodeID && node.NodeID != node.PkgID+prunedSuffix && node.NodeID != node.PkgID {
			overridden++
		}
	}
	assert.NotZero(t, overridden,
		"the upstream fixture should still contain version overrides; if it does not, this test is no longer proving anything")

	for _, node := range mine.Graph.Nodes {
		if node.NodeID == mine.Graph.RootNodeID {
			continue
		}
		assert.Contains(t, []string{node.PkgID, node.PkgID + prunedSuffix}, node.NodeID,
			"this resolver reports resolved versions, so a node's ID always names its own package")
	}
}

const prunedSuffix = ":pruned"

// adjacency maps every node ID to its sorted dependency node IDs.
func adjacency(t *testing.T, graph *godepgraph.DepGraph) map[string][]string {
	t.Helper()

	out := make(map[string][]string, len(graph.Graph.Nodes))

	for _, node := range graph.Graph.Nodes {
		deps := make([]string, 0, len(node.Deps))
		for _, dep := range node.Deps {
			deps = append(deps, dep.NodeID)
		}
		sort.Strings(deps)

		_, duplicate := out[node.NodeID]
		require.False(t, duplicate, "node %s appears twice", node.NodeID)

		out[node.NodeID] = deps
	}

	return out
}

// prunedLabels maps each pruned node to the labels it carries.
func prunedLabels(graph *godepgraph.DepGraph) map[string]map[string]string {
	out := map[string]map[string]string{}

	for _, node := range graph.Graph.Nodes {
		if !strings.HasSuffix(node.NodeID, prunedSuffix) || node.NodeID == prunedSuffix {
			continue
		}

		var labels map[string]string
		if node.Info != nil {
			labels = node.Info.Labels
		}

		out[node.NodeID] = labels
	}

	return out
}

// packageNames lists the distinct package names in a graph, sorted.
func packageNames(graph *godepgraph.DepGraph) []string {
	seen := map[string]struct{}{}
	for _, pkg := range graph.Pkgs {
		seen[pkg.Info.Name] = struct{}{}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
