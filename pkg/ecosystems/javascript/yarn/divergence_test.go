package yarn_test

// divergence_test.go quantifies how this plugin's output diverges from
// nodejs-lockfile-parser's TS-side output for the same fixture inputs.
//
// Each fixture dir may carry a `legacy_expected.json` — the dep graph that
// `nodejs-lockfile-parser` produces for the same package.json + yarn.lock.
// We load both, normalize away cosmetic differences (pkg/node ordering,
// per-node `info.labels.scope` that the Go plugins in this repo by convention
// don't emit), and assert the pkg set and edge set match.
//
// Real divergences fail the test loudly; legitimate format differences
// (ordering, labels) are normalized out. Fixtures without a legacy golden
// are skipped silently so the suite is additive.
//
// This guards against behavioural drift from the legacy parser as we evolve
// the new plugin.
//
// Run with: go test -run TestLegacyDivergence ./pkg/ecosystems/javascript/yarn/...

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/yarn"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// TestLegacyDivergence runs the plugin against each fixture under
// testdata/fixtures/classic-* and, if a legacy_expected.json is present,
// asserts pkg set + edge set parity with what nodejs-lockfile-parser
// produced for the same input.
func TestLegacyDivergence(t *testing.T) {
	requireYarn(t, 1)

	fixtures, err := filepath.Glob("testdata/fixtures/classic-*")
	require.NoError(t, err)
	require.NotEmpty(t, fixtures)

	plugin := yarn.Plugin{}

	for _, srcDir := range fixtures {
		name := filepath.Base(srcDir)
		t.Run(name, func(t *testing.T) {
			legacyPath := filepath.Join(srcDir, "legacy_expected.json")
			if _, err := os.Stat(legacyPath); errors.Is(err, os.ErrNotExist) {
				t.Skipf("no legacy_expected.json for %s", name)
			}

			dir := t.TempDir()
			copyTreeForAcceptance(t, srcDir, dir)
			// Strip the legacy golden from the staged copy — it's a test
			// artifact, not an input to yarn.
			_ = os.Remove(filepath.Join(dir, "legacy_expected.json"))

			results, err := scatest.Run(context.Background(), plugin, logger.Nop(), dir,
				&ecosystems.SCAPluginOptions{})
			require.NoError(t, err)
			require.NotEmpty(t, results)

			ours := unionSummary(results)
			legacy := loadLegacySummary(t, legacyPath)

			assertSummariesEqual(t, name, legacy, ours)
		})
	}
}

// graphSummary is the normalized comparison shape: a sorted pkg list and a
// sorted edge list. Ordering is canonical so map iteration order in either
// the TS or Go implementation can't cause spurious diffs.
type graphSummary struct {
	Pkgs  []pkgSummary
	Edges []edgeSummary
}

type pkgSummary struct {
	ID      string
	Name    string
	Version string
}

type edgeSummary struct {
	From string
	To   string
}

// unionSummary collapses every SCAResult's dep graph into one normalized
// summary. Workspace fixtures emit per-workspace SCAResults; the union is
// what makes sense to compare against the legacy parser's flat output.
func unionSummary(results []ecosystems.SCAResult) graphSummary {
	pkgs := make(map[string]pkgSummary)
	edges := make(map[edgeSummary]struct{})

	for _, r := range results {
		if r.DepGraph == nil {
			continue
		}
		for _, p := range r.DepGraph.Pkgs {
			pkgs[p.ID] = pkgSummary{ID: p.ID, Name: p.Info.Name, Version: p.Info.Version}
		}
		// Build nodeId → pkgId so edges are recorded between PKGS, not nodes,
		// matching what's meaningful to compare across implementations that
		// may assign different nodeIds.
		nodeToPkg := make(map[string]string, len(r.DepGraph.Graph.Nodes))
		for _, n := range r.DepGraph.Graph.Nodes {
			nodeToPkg[n.NodeID] = n.PkgID
		}
		for _, n := range r.DepGraph.Graph.Nodes {
			fromPkg, ok := nodeToPkg[n.NodeID]
			if !ok {
				continue
			}
			for _, d := range n.Deps {
				toPkg, ok := nodeToPkg[d.NodeID]
				if !ok {
					continue
				}
				edges[edgeSummary{From: fromPkg, To: toPkg}] = struct{}{}
			}
		}
	}

	return graphSummary{
		Pkgs:  sortedPkgs(pkgs),
		Edges: sortedEdges(edges),
	}
}

// legacyDepGraph is just enough of the Snyk dep-graph schema 1.3.0 to
// extract pkg+edge sets. We ignore the rest (schemaVersion, pkgManager,
// per-node info.labels) — those are cosmetic for divergence-checking
// purposes.
type legacyDepGraph struct {
	Pkgs []struct {
		ID   string `json:"id"`
		Info struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"info"`
	} `json:"pkgs"`
	Graph struct {
		Nodes []struct {
			NodeID string `json:"nodeId"`
			PkgID  string `json:"pkgId"`
			Deps   []struct {
				NodeID string `json:"nodeId"`
			} `json:"deps"`
		} `json:"nodes"`
	} `json:"graph"`
}

// loadLegacySummary loads a TS-side expected.json and normalizes it into the
// same comparison shape we produce from our plugin. Edges are recorded
// between pkg IDs (not node IDs) so naming conventions on nodes don't
// matter — only the package-level dependency topology.
//
// One known cosmetic divergence is normalized here: when package.json has no
// `version` field, the TS parser emits the root pkg ID as "name@" (empty
// version segment). Our Go plugin (and bun's) defaults to "name@0.0.0" so
// the ID is a valid `name@version`. We rewrite "name@" → "name@0.0.0" on the
// legacy side so the divergence check focuses on semantic differences
// rather than this format choice.
func loadLegacySummary(t *testing.T, path string) graphSummary {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var dg legacyDepGraph
	require.NoError(t, json.Unmarshal(data, &dg))

	pkgs := make(map[string]pkgSummary)
	pkgIDRewrite := make(map[string]string) // original → normalized
	for _, p := range dg.Pkgs {
		id, version := p.ID, p.Info.Version
		if version == "" {
			version = "0.0.0"
			id = p.Info.Name + "@" + version
			pkgIDRewrite[p.ID] = id
		}
		pkgs[id] = pkgSummary{ID: id, Name: p.Info.Name, Version: version}
	}

	rewritePkgID := func(id string) string {
		if newID, ok := pkgIDRewrite[id]; ok {
			return newID
		}
		return id
	}

	nodeToPkg := make(map[string]string, len(dg.Graph.Nodes))
	for _, n := range dg.Graph.Nodes {
		nodeToPkg[n.NodeID] = rewritePkgID(n.PkgID)
	}
	edges := make(map[edgeSummary]struct{})
	for _, n := range dg.Graph.Nodes {
		fromPkg, ok := nodeToPkg[n.NodeID]
		if !ok {
			continue
		}
		for _, d := range n.Deps {
			toPkg, ok := nodeToPkg[d.NodeID]
			if !ok {
				continue
			}
			edges[edgeSummary{From: fromPkg, To: toPkg}] = struct{}{}
		}
	}

	return graphSummary{
		Pkgs:  sortedPkgs(pkgs),
		Edges: sortedEdges(edges),
	}
}

// assertSummariesEqual compares two normalized summaries and emits a clear
// per-set diff so a divergence is obvious without re-running the test.
func assertSummariesEqual(t *testing.T, fixture string, legacy, ours graphSummary) {
	t.Helper()

	legacyPkgs := pkgIDSet(legacy.Pkgs)
	oursPkgs := pkgIDSet(ours.Pkgs)
	onlyLegacy := setDifference(legacyPkgs, oursPkgs)
	onlyOurs := setDifference(oursPkgs, legacyPkgs)

	if len(onlyLegacy) > 0 || len(onlyOurs) > 0 {
		t.Errorf("pkg sets diverge for %s:\n  in legacy only: %v\n  in ours only:   %v",
			fixture, onlyLegacy, onlyOurs)
	}

	legacyEdges := edgeSet(legacy.Edges)
	oursEdges := edgeSet(ours.Edges)
	onlyLegacyE := setDifference(legacyEdges, oursEdges)
	onlyOursE := setDifference(oursEdges, legacyEdges)

	if len(onlyLegacyE) > 0 || len(onlyOursE) > 0 {
		t.Errorf("edge sets diverge for %s:\n  in legacy only: %v\n  in ours only:   %v",
			fixture, onlyLegacyE, onlyOursE)
	}

	// Belt-and-braces: also assert lengths so a zero-diff case isn't silently
	// hiding a wholesale mismatch (e.g. both ends produced empty graphs).
	assert.Equal(t, len(legacy.Pkgs), len(ours.Pkgs), "%s: pkg count", fixture)
	assert.Equal(t, len(legacy.Edges), len(ours.Edges), "%s: edge count", fixture)
}

func sortedPkgs(m map[string]pkgSummary) []pkgSummary {
	out := make([]pkgSummary, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func sortedEdges(m map[edgeSummary]struct{}) []edgeSummary {
	out := make([]edgeSummary, 0, len(m))
	for e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}

func pkgIDSet(pkgs []pkgSummary) map[string]struct{} {
	out := make(map[string]struct{}, len(pkgs))
	for _, p := range pkgs {
		out[p.ID] = struct{}{}
	}
	return out
}

func edgeSet(edges []edgeSummary) map[string]struct{} {
	out := make(map[string]struct{}, len(edges))
	for _, e := range edges {
		out[fmt.Sprintf("%s -> %s", e.From, e.To)] = struct{}{}
	}
	return out
}

func setDifference(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
