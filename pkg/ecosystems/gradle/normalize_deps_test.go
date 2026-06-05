//go:build !integration

package gradle

import (
	"context"
	"errors"
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// makeDepGraph builds a minimal DepGraph from a slice of pkgs and a
// parent-child edge list. Node IDs match pkg IDs for ease of reading.
// The first pkg becomes the root.
func makeDepGraph(t *testing.T, pkgs []depgraph.Pkg, edges [][2]string) *depgraph.DepGraph {
	t.Helper()
	nodes := make([]depgraph.Node, len(pkgs))
	for i, pkg := range pkgs {
		nodes[i] = depgraph.Node{
			NodeID: pkg.ID,
			PkgID:  pkg.ID,
			Deps:   []depgraph.Dependency{},
		}
	}
	nodeByID := make(map[string]*depgraph.Node, len(nodes))
	for i := range nodes {
		nodeByID[nodes[i].NodeID] = &nodes[i]
	}
	for _, edge := range edges {
		parent, ok := nodeByID[edge[0]]
		require.True(t, ok, "edge references unknown parent %q", edge[0])
		_, ok = nodeByID[edge[1]]
		require.True(t, ok, "edge references unknown child %q", edge[1])
		parent.Deps = append(parent.Deps, depgraph.Dependency{NodeID: edge[1]})
	}
	return &depgraph.DepGraph{
		SchemaVersion: "1.3.0",
		PkgManager:    depgraph.PkgManager{Name: pkgManagerName},
		Pkgs:          pkgs,
		Graph: depgraph.Graph{
			RootNodeID: pkgs[0].ID,
			Nodes:      nodes,
		},
	}
}

// pkgByID returns the (single) pkg with the given ID, or fails the test.
func pkgByID(t *testing.T, dg *depgraph.DepGraph, id string) depgraph.Pkg {
	t.Helper()
	for _, pkg := range dg.Pkgs {
		if pkg.ID == id {
			return pkg
		}
	}
	t.Fatalf("pkg %q not found", id)
	return depgraph.Pkg{}
}

func TestParseMavenPurl(t *testing.T) {
	tests := []struct {
		name      string
		purl      string
		wantOK    bool
		wantSha1  string
		wantGroup string
		wantArt   string
		wantVer   string
	}{
		{
			name:      "valid maven purl with sha1",
			purl:      "pkg:maven/com.example/foo@1.2.3?checksum=sha1:abc123",
			wantOK:    true,
			wantSha1:  "abc123",
			wantGroup: "com.example",
			wantArt:   "foo",
			wantVer:   "1.2.3",
		},
		{
			name:   "missing checksum qualifier",
			purl:   "pkg:maven/com.example/foo@1.2.3",
			wantOK: false,
		},
		{
			name:   "non-maven type",
			purl:   "pkg:npm/foo@1.0.0?checksum=sha1:abc",
			wantOK: false,
		},
		{
			name:   "non-sha1 checksum",
			purl:   "pkg:maven/com.example/foo@1.2.3?checksum=md5:abc",
			wantOK: false,
		},
		{
			name:   "empty string",
			purl:   "",
			wantOK: false,
		},
		{
			name:   "malformed purl",
			purl:   "not-a-purl",
			wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sha1, coords, ok := parseMavenPurl(tc.purl)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantSha1, sha1)
				assert.Equal(t, tc.wantGroup, coords.groupID)
				assert.Equal(t, tc.wantArt, coords.artifact)
				assert.Equal(t, tc.wantVer, coords.version)
			}
		})
	}
}

func TestCollectShaLookups_DedupesAcrossGraphs(t *testing.T) {
	// Two distinct graphs both reference the same SHA1 — the lookup map
	// should contain it exactly once. A second SHA1 appears only in graph B
	// and must still be picked up.
	graphA := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		{ID: "shared@1", Info: depgraph.PkgInfo{
			Name:       "shared",
			Version:    "1",
			PackageURL: "pkg:maven/g/shared@1?checksum=sha1:SHARED",
		}},
	}, [][2]string{{"root@1", "shared@1"}})
	graphB := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@2", Info: depgraph.PkgInfo{Name: "root", Version: "2"}},
		{ID: "shared@1", Info: depgraph.PkgInfo{
			Name:       "shared",
			Version:    "1",
			PackageURL: "pkg:maven/g/shared@1?checksum=sha1:SHARED",
		}},
		{ID: "other@1", Info: depgraph.PkgInfo{
			Name:       "other",
			Version:    "1",
			PackageURL: "pkg:maven/g/other@1?checksum=sha1:OTHER",
		}},
	}, [][2]string{{"root@2", "shared@1"}, {"root@2", "other@1"}})

	results := []ecosystems.SCAResult{{DepGraph: graphA}, {DepGraph: graphB}}
	lookups := collectShaLookups(results)

	require.Len(t, lookups, 2)
	assert.Equal(t, mavenCoords{"g", "shared", "1"}, lookups["SHARED"])
	assert.Equal(t, mavenCoords{"g", "other", "1"}, lookups["OTHER"])
}

func TestCollectShaLookups_SkipsPkgsWithoutSha1(t *testing.T) {
	graph := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		{ID: "no-purl@1", Info: depgraph.PkgInfo{Name: "no-purl", Version: "1"}},
		{ID: "no-sha1@1", Info: depgraph.PkgInfo{
			Name:       "no-sha1",
			Version:    "1",
			PackageURL: "pkg:maven/g/no-sha1@1",
		}},
		{ID: "with-sha1@1", Info: depgraph.PkgInfo{
			Name:       "with-sha1",
			Version:    "1",
			PackageURL: "pkg:maven/g/with-sha1@1?checksum=sha1:HASH",
		}},
	}, nil)

	lookups := collectShaLookups([]ecosystems.SCAResult{{DepGraph: graph}})

	require.Len(t, lookups, 1)
	assert.Contains(t, lookups, "HASH")
}

func TestPostHook_RewritesGraphFromCanonicalCoords(t *testing.T) {
	graph := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		{ID: "orig:lib@OLD", Info: depgraph.PkgInfo{
			Name:       "orig:lib",
			Version:    "OLD",
			PackageURL: "pkg:maven/orig/lib@OLD?checksum=sha1:H1",
		}},
	}, [][2]string{{"root@1", "orig:lib@OLD"}})

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon/lib@NEW"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	require.Len(t, results, 1)
	out := results[0].DepGraph
	require.NotNil(t, out)

	// The rewritten pkg uses canonical name and version, and the checksum
	// qualifier is preserved (IncludeProvenance=true).
	pkg := pkgByID(t, out, "canon:lib@NEW")
	assert.Equal(t, "canon:lib", pkg.Info.Name)
	assert.Equal(t, "NEW", pkg.Info.Version)
	assert.Equal(t, "pkg:maven/canon/lib@NEW?checksum=sha1%3AH1", pkg.Info.PackageURL)

	// The node IDs are stable; only PkgID rewrites. The "orig:lib@OLD" node
	// must now reference the canonical pkg.
	var foundNode *depgraph.Node
	for i := range out.Graph.Nodes {
		if out.Graph.Nodes[i].NodeID == "orig:lib@OLD" {
			foundNode = &out.Graph.Nodes[i]
			break
		}
	}
	require.NotNil(t, foundNode, "expected node 'orig:lib@OLD' to be preserved")
	assert.Equal(t, "canon:lib@NEW", foundNode.PkgID)
}

func TestPostHook_LeavesUnresolvedSha1Untouched(t *testing.T) {
	graph := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		{ID: "orig:lib@OLD", Info: depgraph.PkgInfo{
			Name:       "orig:lib",
			Version:    "OLD",
			PackageURL: "pkg:maven/orig/lib@OLD?checksum=sha1:H_UNKNOWN",
		}},
	}, [][2]string{{"root@1", "orig:lib@OLD"}})

	fake := newFakeLookuper()
	// No response configured: API returns "no mapping" for this SHA1.

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	out := results[0].DepGraph
	pkg := pkgByID(t, out, "orig:lib@OLD")
	assert.Equal(t, "orig:lib", pkg.Info.Name)
	assert.Equal(t, "OLD", pkg.Info.Version)
	// purl preserved untouched.
	assert.Equal(t, "pkg:maven/orig/lib@OLD?checksum=sha1:H_UNKNOWN", pkg.Info.PackageURL)
}

func TestPostHook_StripsPurlsWhenProvenanceDisabled(t *testing.T) {
	graph := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		// One pkg with a canonical mapping…
		{ID: "orig:lib@OLD", Info: depgraph.PkgInfo{
			Name:       "orig:lib",
			Version:    "OLD",
			PackageURL: "pkg:maven/orig/lib@OLD?checksum=sha1:H1",
		}},
		// …and one without (API will not return a mapping).
		{ID: "unmapped:lib@1", Info: depgraph.PkgInfo{
			Name:       "unmapped:lib",
			Version:    "1",
			PackageURL: "pkg:maven/unmapped/lib@1?checksum=sha1:H_NONE",
		}},
	}, [][2]string{{"root@1", "orig:lib@OLD"}, {"root@1", "unmapped:lib@1"}})

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon/lib@NEW"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		// IncludeProvenance not set → user did not ask for purls in the
		// output; we should strip them after normalisation.
		&ecosystems.SCAPluginOptions{},
	)

	out := results[0].DepGraph
	// Every pkg in the output (including the un-rewritten one) should have an
	// empty PackageURL.
	for _, pkg := range out.Pkgs {
		assert.Empty(t, pkg.Info.PackageURL,
			"expected purl stripped for %s when --include-provenance is off", pkg.ID)
	}
	// The canonical rewrite still applied (we just dropped the purl).
	pkgByID(t, out, "canon:lib@NEW")
}

func TestPostHook_MergesCollidingPkgsAfterRewrite(t *testing.T) {
	// Two distinct originals (different SHA1s, e.g. different jar files)
	// resolve to the same canonical GAV. The result should be a single pkg in
	// the merged graph, with both original nodes pointing at it.
	graph := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		{ID: "a:lib@OLD1", Info: depgraph.PkgInfo{
			Name:       "a:lib",
			Version:    "OLD1",
			PackageURL: "pkg:maven/a/lib@OLD1?checksum=sha1:H1",
		}},
		{ID: "b:lib@OLD2", Info: depgraph.PkgInfo{
			Name:       "b:lib",
			Version:    "OLD2",
			PackageURL: "pkg:maven/b/lib@OLD2?checksum=sha1:H2",
		}},
	}, [][2]string{{"root@1", "a:lib@OLD1"}, {"root@1", "b:lib@OLD2"}})

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon/lib@NEW"
	fake.responses["H2"] = "pkg:maven/canon/lib@NEW"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	out := results[0].DepGraph

	// Exactly one canonical pkg, plus root.
	canonicalCount := 0
	for _, pkg := range out.Pkgs {
		if pkg.ID == "canon:lib@NEW" {
			canonicalCount++
		}
	}
	assert.Equal(t, 1, canonicalCount, "expected duplicate canonical pkgs to be merged")
	assert.Len(t, out.Pkgs, 2, "expected exactly root + 1 canonical pkg")

	// Both original nodes should now reference the canonical pkg.
	pkgIDsByNode := make(map[string]string)
	for _, node := range out.Graph.Nodes {
		pkgIDsByNode[node.NodeID] = node.PkgID
	}
	assert.Equal(t, "canon:lib@NEW", pkgIDsByNode["a:lib@OLD1"])
	assert.Equal(t, "canon:lib@NEW", pkgIDsByNode["b:lib@OLD2"])
}

func TestPostHook_NoOpsWhenOrgIDEmpty(t *testing.T) {
	graph := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		{ID: "orig:lib@OLD", Info: depgraph.PkgInfo{
			Name:       "orig:lib",
			Version:    "OLD",
			PackageURL: "pkg:maven/orig/lib@OLD?checksum=sha1:H1",
		}},
	}, [][2]string{{"root@1", "orig:lib@OLD"}})

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon/lib@NEW"

	hook := newNormalizeDepsPostHookWithClient(fake, "")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	// Graph returned unchanged; no lookups performed.
	assert.Equal(t, int64(0), fake.totalCalls.Load())
	out := results[0].DepGraph
	pkgByID(t, out, "orig:lib@OLD")
}

func TestPostHook_TreatsAPIErrorsAsUnmapped(t *testing.T) {
	graph := makeDepGraph(t, []depgraph.Pkg{
		{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
		{ID: "ok:lib@OLD", Info: depgraph.PkgInfo{
			Name:       "ok:lib",
			Version:    "OLD",
			PackageURL: "pkg:maven/ok/lib@OLD?checksum=sha1:H_OK",
		}},
		{ID: "bad:lib@OLD", Info: depgraph.PkgInfo{
			Name:       "bad:lib",
			Version:    "OLD",
			PackageURL: "pkg:maven/bad/lib@OLD?checksum=sha1:H_ERR",
		}},
	}, [][2]string{{"root@1", "ok:lib@OLD"}, {"root@1", "bad:lib@OLD"}})

	fake := newFakeLookuper()
	fake.responses["H_OK"] = "pkg:maven/canon/lib@NEW"
	fake.errors["H_ERR"] = errors.New("simulated network failure")

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	out := results[0].DepGraph

	// Successful lookup rewrote its pkg.
	pkgByID(t, out, "canon:lib@NEW")
	// Failed lookup left its pkg as-is.
	pkg := pkgByID(t, out, "bad:lib@OLD")
	assert.Equal(t, "pkg:maven/bad/lib@OLD?checksum=sha1:H_ERR", pkg.Info.PackageURL)
}

func TestPostHook_IssuesOneLookupPerUniqueSha1(t *testing.T) {
	// The same SHA1 referenced from three graphs and several pkgs must
	// result in exactly one API call.
	makeGraph := func(rootID, pkgID, purl string) *depgraph.DepGraph {
		return makeDepGraph(t, []depgraph.Pkg{
			{ID: rootID, Info: depgraph.PkgInfo{Name: rootID, Version: "1"}},
			{ID: pkgID, Info: depgraph.PkgInfo{
				Name:       "lib",
				Version:    "1",
				PackageURL: purl,
			}},
		}, [][2]string{{rootID, pkgID}})
	}
	purl := "pkg:maven/g/lib@1?checksum=sha1:H1"
	results := []ecosystems.SCAResult{
		{DepGraph: makeGraph("rA@1", "lib@1", purl)},
		{DepGraph: makeGraph("rB@1", "lib@1", purl)},
		{DepGraph: makeGraph("rC@1", "lib@1", purl)},
	}

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon/lib@2"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	_ = hook(context.Background(), logger.Nop(), results,
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	assert.Equal(t, 1, fake.callCount("H1"), "expected SHA1 lookup to be deduped across graphs")
	assert.Equal(t, int64(1), fake.totalCalls.Load())
}

func TestPostHook_PreservesNilDepGraphResults(t *testing.T) {
	// Error results (DepGraph == nil) must pass through cleanly.
	fake := newFakeLookuper()
	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: nil}, {DepGraph: nil}},
		&ecosystems.SCAPluginOptions{},
	)
	require.Len(t, results, 2)
	assert.Nil(t, results[0].DepGraph)
	assert.Nil(t, results[1].DepGraph)
	assert.Equal(t, int64(0), fake.totalCalls.Load())
}

func TestPostHook_HandlesSuffixedNodeIDs(t *testing.T) {
	// Test that nodes with suffixed PkgIDs (like constraint and pruned nodes)
	// are correctly rewritten to reference the canonical packages while
	// preserving their suffixes.
	graph := &depgraph.DepGraph{
		SchemaVersion: "1.3.0",
		PkgManager:    depgraph.PkgManager{Name: pkgManagerName},
		Pkgs: []depgraph.Pkg{
			{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
			{ID: "orig:lib@OLD", Info: depgraph.PkgInfo{
				Name:       "orig:lib",
				Version:    "OLD",
				PackageURL: "pkg:maven/orig/lib@OLD?checksum=sha1:H1",
			}},
		},
		Graph: depgraph.Graph{
			RootNodeID: "root@1",
			Nodes: []depgraph.Node{
				{NodeID: "root@1", PkgID: "root@1", Deps: []depgraph.Dependency{
					{NodeID: "orig:lib@OLD"},
					{NodeID: "orig:lib@OLD:constraint"},
					{NodeID: "orig:lib@OLD:pruned"},
				}},
				{NodeID: "orig:lib@OLD", PkgID: "orig:lib@OLD", Deps: []depgraph.Dependency{}},
				// Constraint node with suffixed PkgID
				{NodeID: "orig:lib@OLD:constraint", PkgID: "orig:lib@OLD:constraint", Deps: []depgraph.Dependency{}},
				// Pruned node with suffixed PkgID
				{NodeID: "orig:lib@OLD:pruned", PkgID: "orig:lib@OLD:pruned", Deps: []depgraph.Dependency{}},
			},
		},
	}

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon/lib@NEW"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	out := results[0].DepGraph
	require.NotNil(t, out)

	// The canonical package should exist
	canonicalPkg := pkgByID(t, out, "canon:lib@NEW")
	assert.Equal(t, "canon:lib", canonicalPkg.Info.Name)
	assert.Equal(t, "NEW", canonicalPkg.Info.Version)

	// Build a map of NodeID -> PkgID for easy verification
	pkgIDsByNode := make(map[string]string)
	for _, node := range out.Graph.Nodes {
		pkgIDsByNode[node.NodeID] = node.PkgID
	}

	// Verify that all nodes now reference the canonical package ID,
	// with suffixes preserved
	assert.Equal(t, "canon:lib@NEW", pkgIDsByNode["orig:lib@OLD"], "base node should reference canonical package")
	assert.Equal(t, "canon:lib@NEW:constraint", pkgIDsByNode["orig:lib@OLD:constraint"], "constraint node should reference canonical package with :constraint suffix")
	assert.Equal(t, "canon:lib@NEW:pruned", pkgIDsByNode["orig:lib@OLD:pruned"], "pruned node should reference canonical package with :pruned suffix")
}

func TestPostHook_HandlesCustomSuffixes(t *testing.T) {
	// Test that the suffix-aware logic works for any suffix pattern, not just
	// the hardcoded :constraint and :pruned ones.
	graph := &depgraph.DepGraph{
		SchemaVersion: "1.3.0",
		PkgManager:    depgraph.PkgManager{Name: pkgManagerName},
		Pkgs: []depgraph.Pkg{
			{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
			{ID: "orig:lib@OLD", Info: depgraph.PkgInfo{
				Name:       "orig:lib",
				Version:    "OLD",
				PackageURL: "pkg:maven/orig/lib@OLD?checksum=sha1:H1",
			}},
		},
		Graph: depgraph.Graph{
			RootNodeID: "root@1",
			Nodes: []depgraph.Node{
				{NodeID: "root@1", PkgID: "root@1", Deps: []depgraph.Dependency{
					{NodeID: "orig:lib@OLD:custom-suffix"},
					{NodeID: "orig:lib@OLD:another:complex:suffix"},
				}},
				// Custom suffix patterns
				{NodeID: "orig:lib@OLD:custom-suffix", PkgID: "orig:lib@OLD:custom-suffix", Deps: []depgraph.Dependency{}},
				{NodeID: "orig:lib@OLD:another:complex:suffix", PkgID: "orig:lib@OLD:another:complex:suffix", Deps: []depgraph.Dependency{}},
			},
		},
	}

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon/lib@NEW"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	out := results[0].DepGraph
	require.NotNil(t, out)

	// Build a map of NodeID -> PkgID for easy verification
	pkgIDsByNode := make(map[string]string)
	for _, node := range out.Graph.Nodes {
		pkgIDsByNode[node.NodeID] = node.PkgID
	}

	// Verify that custom suffixes are preserved
	assert.Equal(t, "canon:lib@NEW:custom-suffix", pkgIDsByNode["orig:lib@OLD:custom-suffix"], "custom suffix should be preserved")
	assert.Equal(t, "canon:lib@NEW:another:complex:suffix", pkgIDsByNode["orig:lib@OLD:another:complex:suffix"], "complex suffix should be preserved")
}

func TestPostHook_HandlesLongestPrefixMatching(t *testing.T) {
	// Test that the longest-prefix matching works correctly when one package ID
	// is a prefix of another (edge case prevention).
	graph := &depgraph.DepGraph{
		SchemaVersion: "1.3.0",
		PkgManager:    depgraph.PkgManager{Name: pkgManagerName},
		Pkgs: []depgraph.Pkg{
			{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
			{ID: "short@1", Info: depgraph.PkgInfo{
				Name:       "short",
				Version:    "1",
				PackageURL: "pkg:maven/short/lib@1?checksum=sha1:H1",
			}},
			{ID: "short@1-extended", Info: depgraph.PkgInfo{
				Name:       "short-extended",
				Version:    "1",
				PackageURL: "pkg:maven/short/extended@1?checksum=sha1:H2",
			}},
		},
		Graph: depgraph.Graph{
			RootNodeID: "root@1",
			Nodes: []depgraph.Node{
				{NodeID: "root@1", PkgID: "root@1", Deps: []depgraph.Dependency{
					{NodeID: "short@1:suffix"},
					{NodeID: "short@1-extended:suffix"},
				}},
				// Node with suffix that could match multiple prefixes
				{NodeID: "short@1:suffix", PkgID: "short@1:suffix", Deps: []depgraph.Dependency{}},
				{NodeID: "short@1-extended:suffix", PkgID: "short@1-extended:suffix", Deps: []depgraph.Dependency{}},
			},
		},
	}

	fake := newFakeLookuper()
	fake.responses["H1"] = "pkg:maven/canon-short/lib@2"
	fake.responses["H2"] = "pkg:maven/canon-extended/lib@2"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	out := results[0].DepGraph
	require.NotNil(t, out)

	// Build a map of NodeID -> PkgID for easy verification
	pkgIDsByNode := make(map[string]string)
	for _, node := range out.Graph.Nodes {
		pkgIDsByNode[node.NodeID] = node.PkgID
	}

	// Verify that longest prefix matching worked correctly
	assert.Equal(t, "canon-short:lib@2:suffix", pkgIDsByNode["short@1:suffix"], "should match 'short@1' not a substring")
	assert.Equal(t, "canon-extended:lib@2:suffix", pkgIDsByNode["short@1-extended:suffix"], "should match full 'short@1-extended' prefix")
}

func TestPostHook_HandlesSuffixedNodesWithMerging(t *testing.T) {
	// Test that suffix-aware node rewriting works correctly when multiple
	// original packages get merged into a single canonical package, and some
	// of those have suffixed nodes (constraint/pruned).
	graph := &depgraph.DepGraph{
		SchemaVersion: "1.3.0",
		PkgManager:    depgraph.PkgManager{Name: pkgManagerName},
		Pkgs: []depgraph.Pkg{
			{ID: "root@1", Info: depgraph.PkgInfo{Name: "root", Version: "1"}},
			// Two different original packages that will map to the same canonical
			{ID: "a:lib@OLD1", Info: depgraph.PkgInfo{
				Name:       "a:lib",
				Version:    "OLD1",
				PackageURL: "pkg:maven/a/lib@OLD1?checksum=sha1:H1",
			}},
			{ID: "b:lib@OLD2", Info: depgraph.PkgInfo{
				Name:       "b:lib",
				Version:    "OLD2",
				PackageURL: "pkg:maven/b/lib@OLD2?checksum=sha1:H2",
			}},
		},
		Graph: depgraph.Graph{
			RootNodeID: "root@1",
			Nodes: []depgraph.Node{
				{NodeID: "root@1", PkgID: "root@1", Deps: []depgraph.Dependency{
					{NodeID: "a:lib@OLD1"},
					{NodeID: "a:lib@OLD1:constraint"},
					{NodeID: "b:lib@OLD2"},
					{NodeID: "b:lib@OLD2:pruned"},
				}},
				// Regular nodes
				{NodeID: "a:lib@OLD1", PkgID: "a:lib@OLD1", Deps: []depgraph.Dependency{}},
				{NodeID: "b:lib@OLD2", PkgID: "b:lib@OLD2", Deps: []depgraph.Dependency{}},
				// Suffixed nodes from different originals
				{NodeID: "a:lib@OLD1:constraint", PkgID: "a:lib@OLD1:constraint", Deps: []depgraph.Dependency{}},
				{NodeID: "b:lib@OLD2:pruned", PkgID: "b:lib@OLD2:pruned", Deps: []depgraph.Dependency{}},
			},
		},
	}

	fake := newFakeLookuper()
	// Both different originals map to the same canonical package
	fake.responses["H1"] = "pkg:maven/canon/lib@NEW"
	fake.responses["H2"] = "pkg:maven/canon/lib@NEW"

	hook := newNormalizeDepsPostHookWithClient(fake, "org-1")
	results := hook(context.Background(), logger.Nop(),
		[]ecosystems.SCAResult{{DepGraph: graph}},
		&ecosystems.SCAPluginOptions{Global: ecosystems.GlobalOptions{IncludeProvenance: true}},
	)

	out := results[0].DepGraph
	require.NotNil(t, out)

	// Verify merging: only one canonical package should exist
	canonicalCount := 0
	for _, pkg := range out.Pkgs {
		if pkg.ID == "canon:lib@NEW" {
			canonicalCount++
		}
	}
	assert.Equal(t, 1, canonicalCount, "expected merged packages to result in single canonical pkg")
	assert.Len(t, out.Pkgs, 2, "expected exactly root + 1 canonical pkg")

	// Build a map of NodeID -> PkgID for verification
	pkgIDsByNode := make(map[string]string)
	for _, node := range out.Graph.Nodes {
		pkgIDsByNode[node.NodeID] = node.PkgID
	}

	// All nodes should now reference the canonical package,
	// with suffixes properly preserved
	assert.Equal(t, "canon:lib@NEW", pkgIDsByNode["a:lib@OLD1"], "regular node from package A should reference canonical")
	assert.Equal(t, "canon:lib@NEW", pkgIDsByNode["b:lib@OLD2"], "regular node from package B should reference canonical")
	assert.Equal(t, "canon:lib@NEW:constraint", pkgIDsByNode["a:lib@OLD1:constraint"], "constraint node from package A should reference canonical with suffix")
	assert.Equal(t, "canon:lib@NEW:pruned", pkgIDsByNode["b:lib@OLD2:pruned"], "pruned node from package B should reference canonical with suffix")
}
