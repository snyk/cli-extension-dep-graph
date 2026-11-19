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
	mine, theirs := loadParityGraphs(t)

	assert.Equal(t, theirs.SchemaVersion, mine.SchemaVersion)
	assert.Equal(t, theirs.PkgManager, mine.PkgManager)
	assert.Equal(t, theirs.Graph.RootNodeID, mine.Graph.RootNodeID)

	// Node identities and edges must match exactly. This is the substance of the
	// port: which packages resolved, at which versions, and which depends on
	// which — including the pruned back-edges, whose placement depends on the
	// order siblings are walked in. Upstream is compared with twin edges collapsed.
	theirsNormalized := withoutTwinEdges(adjacency(t, theirs))

	assert.Equal(t, theirsNormalized, adjacency(t, mine), "node and edge sets diverged")

	theirPruned := restrictToKeys(prunedLabels(theirs), theirsNormalized)
	assert.NotEmpty(t, theirPruned,
		"the upstream fixture should still contain pruned nodes; if it does not, this comparison proves nothing")
	assert.Equal(t, theirPruned, prunedLabels(mine), "pruned nodes diverged")

	// Package *versions* are allowed to differ, and do: snyk-nuget-plugin
	// rewrites them from the host SDK's PackageOverrides.txt, which a static
	// resolver cannot read. The set of package names must still be identical.
	assert.Equal(t, packageNames(theirs), packageNames(mine), "package sets diverged")

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

// TestDivergesFromSnykNugetPlugin_TwinEdges verifies we do not emit twin edges
// (parent with both X and X:pruned) while snyk-nuget-plugin does. If the upstream
// fixture is regenerated without twins, this test fails and withoutTwinEdges can be removed.
func TestDivergesFromSnykNugetPlugin_TwinEdges(t *testing.T) {
	mine, theirs := loadParityGraphs(t)

	theirTwins := countTwinEdges(adjacency(t, theirs))
	mineTwins := countTwinEdges(adjacency(t, mine))

	assert.Equal(t, 52, theirTwins, "upstream fixture must have 52 twin edges")
	assert.Equal(t, 0, mineTwins, "this resolver must have 0 twin edges")
}

// loadParityGraphs returns this resolver's graph and snyk-nuget-plugin's graph
// for the dotnet_6 fixture.
func loadParityGraphs(t *testing.T) (mine, theirs *godepgraph.DepGraph) {
	t.Helper()

	dir := filepath.Join("testdata", "parity", "dotnet_6")

	results, err := scatest.Run(t.Context(), nuget.Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "the project targets one framework")
	require.NoError(t, results[0].Error)

	mine = results[0].DepGraph
	require.NotNil(t, mine)

	raw, err := os.ReadFile(filepath.Join(dir, "snyk-nuget-plugin.json"))
	require.NoError(t, err)

	theirs = new(godepgraph.DepGraph)
	require.NoError(t, json.Unmarshal(raw, theirs))

	return mine, theirs
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

// withoutTwinEdges collapses twin edges: when a parent has both X and X:pruned,
// keeps X and drops X:pruned. Unreferenced pruned nodes are removed.
func withoutTwinEdges(adj map[string][]string) map[string][]string {
	normalized := make(map[string][]string, len(adj))
	referenced := make(map[string]bool)

	for parent, deps := range adj {
		hasReal := make(map[string]bool)
		for _, dep := range deps {
			if !strings.HasSuffix(dep, prunedSuffix) {
				hasReal[dep] = true
			}
		}

		filtered := make([]string, 0, len(deps))
		for _, dep := range deps {
			if strings.HasSuffix(dep, prunedSuffix) {
				base := strings.TrimSuffix(dep, prunedSuffix)
				if hasReal[base] {
					continue
				}
			}
			filtered = append(filtered, dep)
			referenced[dep] = true
		}

		normalized[parent] = filtered
	}

	for nodeID := range adj {
		if strings.HasSuffix(nodeID, prunedSuffix) && !referenced[nodeID] {
			delete(normalized, nodeID)
		}
	}

	return normalized
}

// countTwinEdges counts how many children the normalization removes.
func countTwinEdges(adj map[string][]string) int {
	original := 0
	for _, deps := range adj {
		original += len(deps)
	}

	normalized := 0
	for _, deps := range withoutTwinEdges(adj) {
		normalized += len(deps)
	}

	return original - normalized
}

// restrictToKeys filters a map to keys present in the adjacency map.
func restrictToKeys(labels map[string]map[string]string, adj map[string][]string) map[string]map[string]string {
	out := make(map[string]map[string]string, len(labels))
	for nodeID, nodeLabels := range labels {
		if _, exists := adj[nodeID]; exists {
			out[nodeID] = nodeLabels
		}
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
