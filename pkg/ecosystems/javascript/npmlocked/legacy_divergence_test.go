//go:build integration && npm
// +build integration,npm

package npmlocked_test

// legacy_divergence_test.go quantifies how our `npm ls`-based output
// diverges from the snyk-nodejs-lockfile-parser output for fixtures that
// shipped with a golden `legacy-expected.json`.
//
// Divergence is INFORMATIONAL, not gating — the divergences are
// documented in the PR description and are expected (peer-dep coverage,
// bundled-deps visibility, missing-optional handling, etc.). The test
// fails only if the plugin itself errors on a fixture, not if the dep
// graphs disagree.
//
// What it does report:
//
//   * Per-fixture: pkgs only in legacy, only in ours, in both;
//     edges only in legacy, only in ours, in both.
//   * Aggregate at the end: how many fixtures match exactly, partial,
//     totally divergent; the most common pkgs/edges we add or drop.
//
// Run via `make test-npm-integration` and look at the divergence
// summary at the end of the verbose output.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/npmlocked"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// pkgKey identifies a package node by "name@version" — the same form
// our plugin emits and that the legacy expected.json carries.
type pkgKey string

// edgeKey identifies a directed edge in the dep graph.
type edgeKey struct {
	From pkgKey
	To   pkgKey
}

// divergenceSummary captures the size of each set-diff plus a verdict.
type divergenceSummary struct {
	Fixture string

	OursTotal   int
	LegacyTotal int

	PkgsOnlyInOurs   []pkgKey
	PkgsOnlyInLegacy []pkgKey
	PkgsInBoth       int

	EdgesOnlyInOurs   int
	EdgesOnlyInLegacy int
	EdgesInBoth       int
}

// verdict bucketises the per-fixture comparison for aggregate reporting.
func (d divergenceSummary) verdict() string {
	switch {
	case len(d.PkgsOnlyInOurs) == 0 && len(d.PkgsOnlyInLegacy) == 0 &&
		d.EdgesOnlyInOurs == 0 && d.EdgesOnlyInLegacy == 0:
		return "match"
	case d.PkgsInBoth == 0:
		return "totally-divergent"
	case len(d.PkgsOnlyInOurs) > 0 && len(d.PkgsOnlyInLegacy) > 0:
		return "two-way-divergent"
	case len(d.PkgsOnlyInLegacy) > 0:
		return "we-drop"
	default:
		return "we-add"
	}
}

// divergenceCollector aggregates per-fixture summaries for the end-of-run report.
type divergenceCollector struct {
	mu        sync.Mutex
	summaries []divergenceSummary
}

func (c *divergenceCollector) add(s divergenceSummary) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summaries = append(c.summaries, s)
}

func (c *divergenceCollector) report(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	verdicts := map[string]int{}
	for _, s := range c.summaries {
		verdicts[s.verdict()]++
	}

	keys := make([]string, 0, len(verdicts))
	for k := range verdicts {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	t.Logf("=== divergence summary (%d fixtures compared) ===", len(c.summaries))
	for _, k := range keys {
		t.Logf("  %-20s %d", k, verdicts[k])
	}
	t.Logf("================================================")
}

func TestLegacyFixtures_Divergence(t *testing.T) {
	fixtures := discoverLegacyFixtures(t)
	require.NotEmpty(t, fixtures, "no fixtures discovered")

	// Filter to fixtures with a legacy-expected.json to compare against.
	var withGolden []legacyFixture
	for _, fx := range fixtures {
		if fx.HasLegacyExpected {
			withGolden = append(withGolden, fx)
		}
	}
	require.NotEmpty(t, withGolden,
		"no fixtures with legacy-expected.json found — divergence harness has nothing to compare")

	t.Logf("comparing %d fixtures against legacy goldens", len(withGolden))

	plugin := npmlocked.Plugin{}
	collector := &divergenceCollector{}

	for _, fx := range withGolden {
		t.Run(fx.ID(), func(t *testing.T) {
			requireFixtureCompat(t, fx)

			results, err := scatest.Run(context.Background(), plugin, nil, fx.Dir, &ecosystems.SCAPluginOptions{})
			require.NoError(t, err, "plugin returned setup-time error")
			require.NotEmpty(t, results, "plugin returned zero SCAResults")

			// Only the root dep graph is comparable to the legacy parser's
			// expected.json — the legacy parser emits a single graph per
			// project, while we emit one per workspace + root.
			ours := results[0].DepGraph
			require.NotNil(t, ours, "root result has nil DepGraph")

			legacy := loadLegacyExpected(t, fx)

			summary := compareGraphs(fx.ID(), legacy, ours)
			collector.add(summary)

			// Per-fixture log so failures (or surprising divergences) are
			// easy to find in the verbose output.
			t.Logf("verdict=%s | pkgs: +%d -%d ~%d | edges: +%d -%d ~%d",
				summary.verdict(),
				len(summary.PkgsOnlyInOurs), len(summary.PkgsOnlyInLegacy), summary.PkgsInBoth,
				summary.EdgesOnlyInOurs, summary.EdgesOnlyInLegacy, summary.EdgesInBoth)

			if len(summary.PkgsOnlyInLegacy) > 0 && len(summary.PkgsOnlyInLegacy) <= 10 {
				t.Logf("  legacy-only pkgs: %v", summary.PkgsOnlyInLegacy)
			}
			if len(summary.PkgsOnlyInOurs) > 0 && len(summary.PkgsOnlyInOurs) <= 10 {
				t.Logf("  ours-only pkgs:   %v", summary.PkgsOnlyInOurs)
			}
		})
	}

	t.Cleanup(func() { collector.report(t) })
}

// loadLegacyExpected reads and parses legacy-expected.json into a depgraph.
func loadLegacyExpected(t *testing.T, fx legacyFixture) *depgraph.DepGraph {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fx.Dir, "legacy-expected.json"))
	require.NoError(t, err, "reading legacy-expected.json")
	dg, err := depgraph.UnmarshalJSON(raw)
	require.NoError(t, err, "parsing legacy-expected.json")
	return dg
}

// compareGraphs computes the set-diff between two dep graphs.
func compareGraphs(fixture string, legacy, ours *depgraph.DepGraph) divergenceSummary {
	legacyPkgs := pkgSet(legacy)
	oursPkgs := pkgSet(ours)
	legacyEdges := edgeSet(legacy)
	oursEdges := edgeSet(ours)

	s := divergenceSummary{
		Fixture:     fixture,
		OursTotal:   len(oursPkgs),
		LegacyTotal: len(legacyPkgs),
	}

	for p := range oursPkgs {
		if _, ok := legacyPkgs[p]; !ok {
			s.PkgsOnlyInOurs = append(s.PkgsOnlyInOurs, p)
		} else {
			s.PkgsInBoth++
		}
	}
	for p := range legacyPkgs {
		if _, ok := oursPkgs[p]; !ok {
			s.PkgsOnlyInLegacy = append(s.PkgsOnlyInLegacy, p)
		}
	}
	for e := range oursEdges {
		if _, ok := legacyEdges[e]; !ok {
			s.EdgesOnlyInOurs++
		} else {
			s.EdgesInBoth++
		}
	}
	for e := range legacyEdges {
		if _, ok := oursEdges[e]; !ok {
			s.EdgesOnlyInLegacy++
		}
	}

	sort.Slice(s.PkgsOnlyInOurs, func(i, j int) bool { return s.PkgsOnlyInOurs[i] < s.PkgsOnlyInOurs[j] })
	sort.Slice(s.PkgsOnlyInLegacy, func(i, j int) bool { return s.PkgsOnlyInLegacy[i] < s.PkgsOnlyInLegacy[j] })

	return s
}

// pkgSet returns the set of pkgKey values present in dg's Pkgs list.
func pkgSet(dg *depgraph.DepGraph) map[pkgKey]struct{} {
	out := make(map[pkgKey]struct{}, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		out[pkgKey(p.ID)] = struct{}{}
	}
	return out
}

// edgeSet returns the set of (from→to) edges across all nodes of dg.
//
// Multiple nodes may share the same pkgId — we key by node ID to preserve
// the actual edges, then translate via the nodeId→pkgId mapping so the
// comparison is across canonical pkg identities, matching how the legacy
// parser models the graph.
func edgeSet(dg *depgraph.DepGraph) map[edgeKey]struct{} {
	nodePkg := make(map[string]pkgKey, len(dg.Graph.Nodes))
	for _, n := range dg.Graph.Nodes {
		nodePkg[n.NodeID] = pkgKey(n.PkgID)
	}
	out := make(map[edgeKey]struct{})
	for _, n := range dg.Graph.Nodes {
		from, ok := nodePkg[n.NodeID]
		if !ok {
			continue
		}
		for _, d := range n.Deps {
			to, ok := nodePkg[d.NodeID]
			if !ok {
				continue
			}
			out[edgeKey{From: from, To: to}] = struct{}{}
		}
	}
	return out
}

// dump for ad-hoc debugging of a specific fixture during development.
// Not called by any test; left in to make manual inspection easy.
func dumpGraph(t *testing.T, dg *depgraph.DepGraph) { //nolint:unused // dev helper
	t.Helper()
	data, _ := json.MarshalIndent(dg, "", "  ")
	t.Logf("%s", fmt.Sprintf("%s", data))
}
