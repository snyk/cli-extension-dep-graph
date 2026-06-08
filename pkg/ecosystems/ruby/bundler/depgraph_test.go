package bundler

import (
	"errors"
	"testing"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nodeDeps returns the NodeIDs of nodeID's direct dependencies in dg.
func nodeDeps(t *testing.T, dg *godepgraph.DepGraph, nodeID string) []string {
	t.Helper()
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

// pkgIDs returns the set of package IDs present in dg.
func pkgIDs(dg *godepgraph.DepGraph) map[string]bool {
	out := make(map[string]bool, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		out[p.ID] = true
	}
	return out
}

// rootDeps returns the direct dependencies of the root node.
func rootDeps(t *testing.T, dg *godepgraph.DepGraph) []string {
	t.Helper()
	return nodeDeps(t, dg, dg.Graph.RootNodeID)
}

// TestBuildDepGraph_Simple covers the canonical GEM-only flow:
// two top-level deps, one transitive.
func TestBuildDepGraph_Simple(t *testing.T) {
	lf := &Lockfile{
		Specs: map[string]*Spec{
			"json": {Name: "json", Version: "2.0.2"},
			"lynx": {Name: "lynx", Version: "0.4.0"},
		},
		Dependencies: []Dependency{
			{Name: "json"},
			{Name: "lynx"},
		},
	}

	g, err := BuildDepGraph("my-app", "1.0.0", lf)
	require.NoError(t, err)
	require.NotNil(t, g)

	assert.Equal(t, "my-app", g.GetRootPkg().Info.Name)
	assert.Equal(t, "rubygems", g.PkgManager.Name)

	rd := rootDeps(t, g)
	assert.Contains(t, rd, "json@2.0.2")
	assert.Contains(t, rd, "lynx@0.4.0")
}

// TestBuildDepGraph_Transitive covers nested deps and shared ancestry.
func TestBuildDepGraph_Transitive(t *testing.T) {
	lf := &Lockfile{
		Specs: map[string]*Spec{
			"sanitize":      {Name: "sanitize", Version: "4.6.2", Children: []string{"crass", "nokogiri"}},
			"nokogiri":      {Name: "nokogiri", Version: "1.8.5", Children: []string{"mini_portile2"}},
			"mini_portile2": {Name: "mini_portile2", Version: "2.3.0"},
			"crass":         {Name: "crass", Version: "1.0.4"},
		},
		Dependencies: []Dependency{{Name: "sanitize"}},
	}

	g, err := BuildDepGraph("my-app", "1.0.0", lf)
	require.NoError(t, err)

	ids := pkgIDs(g)
	assert.True(t, ids["sanitize@4.6.2"])
	assert.True(t, ids["nokogiri@1.8.5"])
	assert.True(t, ids["mini_portile2@2.3.0"])
	assert.True(t, ids["crass@1.0.4"])

	assert.ElementsMatch(t,
		[]string{"crass@1.0.4", "nokogiri@1.8.5"},
		nodeDeps(t, g, "sanitize@4.6.2"),
	)
	assert.Equal(t,
		[]string{"mini_portile2@2.3.0"},
		nodeDeps(t, g, "nokogiri@1.8.5"),
	)
}

// TestBuildDepGraph_BundlerExclusion verifies the legacy quirk: bundler
// itself is silently dropped from the dep tree, both when it appears in
// DEPENDENCIES and (defensively) when it appears as a child of another
// spec.
func TestBuildDepGraph_BundlerExclusion(t *testing.T) {
	lf := &Lockfile{
		Specs: map[string]*Spec{
			"rake": {Name: "rake", Version: "10.5.0"},
			// Defensive case: some other spec lists bundler as a child.
			"weird": {Name: "weird", Version: "1.0", Children: []string{"bundler", "rake"}},
		},
		Dependencies: []Dependency{
			{Name: "bundler"}, // direct: should be skipped
			{Name: "rake"},
			{Name: "weird"},
		},
	}

	g, err := BuildDepGraph("my-app", "1.0.0", lf)
	require.NoError(t, err)

	ids := pkgIDs(g)
	for id := range ids {
		assert.NotContains(t, id, "bundler@", "bundler must not appear as a graph node")
	}

	// `weird` should have rake as its only child (bundler filtered out).
	assert.Equal(t, []string{"rake@10.5.0"}, nodeDeps(t, g, "weird@1.0"))

	// Direct root deps: rake + weird, no bundler.
	rd := rootDeps(t, g)
	assert.ElementsMatch(t, []string{"rake@10.5.0", "weird@1.0"}, rd)
}

// TestBuildDepGraph_MissingSpec ensures a dep listed in DEPENDENCIES
// but missing from the Specs map is silently dropped (matches legacy).
func TestBuildDepGraph_MissingSpec(t *testing.T) {
	lf := &Lockfile{
		Specs: map[string]*Spec{
			"json": {Name: "json", Version: "2.0.2"},
		},
		Dependencies: []Dependency{
			{Name: "json"},
			{Name: "ghost-gem"}, // not in Specs
		},
	}
	g, err := BuildDepGraph("my-app", "1.0.0", lf)
	require.NoError(t, err)

	rd := rootDeps(t, g)
	assert.Contains(t, rd, "json@2.0.2")
	for _, id := range rd {
		assert.NotContains(t, id, "ghost-gem")
	}
}

// TestBuildDepGraph_Cycle exercises the cycle detector: an A→B→A loop
// must raise CycleError rather than infinite-loop.
func TestBuildDepGraph_Cycle(t *testing.T) {
	lf := &Lockfile{
		Specs: map[string]*Spec{
			"a": {Name: "a", Version: "1.0", Children: []string{"b"}},
			"b": {Name: "b", Version: "2.0", Children: []string{"a"}},
		},
		Dependencies: []Dependency{{Name: "a"}},
	}

	_, err := BuildDepGraph("my-app", "1.0.0", lf)
	require.Error(t, err)
	var ce *CycleError
	assert.True(t, errors.As(err, &ce), "expected *CycleError, got %T", err)
	assert.Equal(t, "a", ce.Gem)
	assert.Contains(t, ce.Chain, "a")
	assert.Contains(t, ce.Chain, "b")
}

// TestBuildDepGraph_DiamondNoFalseCycle verifies that a "diamond"
// dependency (shared transitive) is NOT mistakenly flagged as a cycle.
// This catches the classic visited-set bug where the same node on two
// non-cyclic paths gets miscounted.
func TestBuildDepGraph_DiamondNoFalseCycle(t *testing.T) {
	// root → a, b
	//  a → shared
	//  b → shared
	lf := &Lockfile{
		Specs: map[string]*Spec{
			"a":      {Name: "a", Version: "1", Children: []string{"shared"}},
			"b":      {Name: "b", Version: "1", Children: []string{"shared"}},
			"shared": {Name: "shared", Version: "9.9"},
		},
		Dependencies: []Dependency{{Name: "a"}, {Name: "b"}},
	}

	g, err := BuildDepGraph("my-app", "1.0.0", lf)
	require.NoError(t, err)

	assert.Contains(t, nodeDeps(t, g, "a@1"), "shared@9.9")
	assert.Contains(t, nodeDeps(t, g, "b@1"), "shared@9.9")
}

// TestBuildDepGraph_IncludeDevWired exercises the BuildOptions hook
// (placeholder while Gemfile-level group info isn't surfaced). Today
// this is a no-op: both runs should yield identical graphs.
func TestBuildDepGraph_IncludeDevWired(t *testing.T) {
	lf := &Lockfile{
		Specs:        map[string]*Spec{"json": {Name: "json", Version: "2.0.2"}},
		Dependencies: []Dependency{{Name: "json"}},
	}

	g1, err := BuildDepGraphWithOptions("app", "1.0", lf, BuildOptions{IncludeDev: false})
	require.NoError(t, err)
	g2, err := BuildDepGraphWithOptions("app", "1.0", lf, BuildOptions{IncludeDev: true})
	require.NoError(t, err)

	assert.Equal(t, len(g1.Pkgs), len(g2.Pkgs))
	assert.ElementsMatch(t, rootDeps(t, g1), rootDeps(t, g2))
}

// TestBuildDepGraph_NilLockfile guards public-API misuse.
func TestBuildDepGraph_NilLockfile(t *testing.T) {
	_, err := BuildDepGraph("app", "1", nil)
	assert.Error(t, err)
}

// TestBuildDepGraph_EmptyRoot guards public-API misuse.
func TestBuildDepGraph_EmptyRoot(t *testing.T) {
	_, err := BuildDepGraph("", "1", &Lockfile{Specs: map[string]*Spec{}})
	assert.Error(t, err)
}
