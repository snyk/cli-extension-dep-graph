package nuget

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// buildFramework builds a graph the way emitFrameworkResult does, from a
// declared package list and whatever the .nuspec files said.
func buildFramework(
	t *testing.T,
	declared []declaredPackage,
	children map[string][]declaredPackage,
) *godepgraph.DepGraph {
	t.Helper()

	installed := newPackageSet()
	for _, pkg := range declared {
		installed.add(pkg.name, pkg.version)
	}

	graph, err := buildFrameworkDepGraph(context.Background(), "App", defaultVersion, installed, children)
	require.NoError(t, err)

	return graph
}

func TestBuildFrameworkDepGraph_RootPackage(t *testing.T) {
	installed := newPackageSet()

	graph, err := buildFrameworkDepGraph(context.Background(), "MyApp", "4.5.6", installed, nil)
	require.NoError(t, err)

	assert.Equal(t, pkgManager, graph.PkgManager.Name)
	assert.Equal(t, "MyApp", graph.GetRootPkg().Info.Name)
	assert.Equal(t, "4.5.6", graph.GetRootPkg().Info.Version)
	assert.Equal(t, []string{"MyApp@4.5.6"}, pkgIDs(graph.Pkgs), "a project with nothing installed is root-only")
}

// Every installed package hangs off the root, whether the project asked for it
// or one of its dependencies did. A .NET Framework manifest is a flattened list
// with no record of who pulled what in, so there is nothing else to go on.
func TestBuildFrameworkDepGraph_EveryPackageIsDirect(t *testing.T) {
	graph := buildFramework(t, []declaredPackage{
		{"jQuery", "3.2.1"},
		{"Moment.js", "2.20.1"},
		{"Newtonsoft.Json", "10.0.3"},
	}, nil)

	assert.ElementsMatch(t,
		[]string{"App@0.0.0", "jQuery@3.2.1", "Moment.js@2.20.1", "Newtonsoft.Json@10.0.3"},
		pkgIDs(graph.Pkgs))

	assert.Equal(t,
		[]string{"Moment.js@2.20.1", "Newtonsoft.Json@10.0.3", "jQuery@3.2.1"},
		depsOf(t, graph, graph.Graph.RootNodeID))
}

// The reason .nupkg archives are read at all: a .nuspec routinely names a
// package the manifest never lists, and it becomes part of the reported set.
func TestBuildFrameworkDepGraph_NuspecChildJoinsTheGraph(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"Swagger.Net", "0.5.5"}},
		map[string][]declaredPackage{"Swagger.Net": {{"WebActivator", "1.5.1"}}})

	assert.ElementsMatch(t,
		[]string{"App@0.0.0", "Swagger.Net@0.5.5", "WebActivator@1.5.1"},
		pkgIDs(graph.Pkgs))

	assert.Equal(t, []string{"WebActivator@1.5.1"}, depsOf(t, graph, "Swagger.Net@0.5.5"))
	assert.Equal(t, []string{"Swagger.Net@0.5.5"}, depsOf(t, graph, graph.Graph.RootNodeID),
		"a package reached only through a .nuspec is not a direct dependency of the project")
}

// A .nuspec version is a constraint on what the package needs, not a record of
// what is installed — so where both are known, the installed one wins.
func TestBuildFrameworkDepGraph_InstalledVersionBeatsNuspecConstraint(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"Parent", "1.0.0"}, {"Child", "3.0.0"}},
		map[string][]declaredPackage{"Parent": {{"Child", "[1.0.0,2.0.0)"}}})

	assert.ElementsMatch(t, []string{"App@0.0.0", "Parent@1.0.0", "Child@3.0.0"}, pkgIDs(graph.Pkgs))
	assert.Equal(t, []string{"Child@3.0.0"}, depsOf(t, graph, "Parent@1.0.0"))
}

// A package that is not installed has nothing but the constraint to report,
// range syntax and all. Upstream reports it verbatim too.
func TestBuildFrameworkDepGraph_UninstalledChildKeepsItsConstraint(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"Parent", "1.0.0"}},
		map[string][]declaredPackage{"Parent": {{"Missing", "[1.0.0,2.0.0)"}}})

	assert.Contains(t, pkgIDs(graph.Pkgs), "Missing@[1.0.0,2.0.0)")
}

func TestBuildFrameworkDepGraph_DiamondSharesOneNode(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"Left", "1.0.0"}, {"Right", "1.0.0"}, {"Shared", "2.0.0"}},
		map[string][]declaredPackage{
			"Left":  {{"Shared", "2.0.0"}},
			"Right": {{"Shared", "2.0.0"}},
		})

	assert.ElementsMatch(t,
		[]string{"App@0.0.0", "Left@1.0.0", "Right@1.0.0", "Shared@2.0.0"},
		pkgIDs(graph.Pkgs))

	// The subtree is walked once per route that reaches it, so without edge
	// deduplication the root would list Shared twice over.
	assert.Equal(t, []string{"Shared@2.0.0"}, depsOf(t, graph, "Left@1.0.0"))
	assert.Equal(t, []string{"Shared@2.0.0"}, depsOf(t, graph, "Right@1.0.0"))
	assert.Equal(t,
		[]string{"Left@1.0.0", "Right@1.0.0", "Shared@2.0.0"},
		depsOf(t, graph, graph.Graph.RootNodeID))
}

// snyk-nuget-plugin's buildTree recurses with no guard at all and overflows its
// stack here. The graph this produces has to stay acyclic, so exactly one of
// the two edges survives — the other would close the cycle. Nothing leaves the
// reported set: both packages already hang off the root.
func TestBuildFrameworkDepGraph_CycleTerminates(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"A", "1.0.0"}, {"B", "1.0.0"}},
		map[string][]declaredPackage{
			"A": {{"B", "1.0.0"}},
			"B": {{"A", "1.0.0"}},
		})

	assert.ElementsMatch(t, []string{"App@0.0.0", "A@1.0.0", "B@1.0.0"}, pkgIDs(graph.Pkgs))
	assert.Equal(t, []string{"B@1.0.0"}, depsOf(t, graph, "A@1.0.0"))
	assert.Empty(t, depsOf(t, graph, "B@1.0.0"), "the edge back to A would close the cycle")

	// A `:pruned` leaf would be the project.assets.json path's answer. Here the
	// edge simply goes, because the packages it would join are already reported.
	for _, node := range graph.Graph.Nodes {
		assert.NotContains(t, node.NodeID, prunedNodeSuffix)
	}
}

// A three-package cycle is broken in exactly one place, wherever the walk first
// comes back on itself.
func TestBuildFrameworkDepGraph_LongerCycleTerminates(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"A", "1.0.0"}, {"B", "1.0.0"}, {"C", "1.0.0"}},
		map[string][]declaredPackage{
			"A": {{"B", "1.0.0"}},
			"B": {{"C", "1.0.0"}},
			"C": {{"A", "1.0.0"}},
		})

	assert.Equal(t, []string{"B@1.0.0"}, depsOf(t, graph, "A@1.0.0"))
	assert.Equal(t, []string{"C@1.0.0"}, depsOf(t, graph, "B@1.0.0"))
	assert.Empty(t, depsOf(t, graph, "C@1.0.0"))
}

func TestBuildFrameworkDepGraph_SelfDependency(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"A", "1.0.0"}},
		map[string][]declaredPackage{"A": {{"A", "1.0.0"}}})

	assert.ElementsMatch(t, []string{"App@0.0.0", "A@1.0.0"}, pkgIDs(graph.Pkgs))
	assert.Empty(t, depsOf(t, graph, "A@1.0.0"))
}

// A child's own dependencies are found by looking its name up in the .nuspec
// map, so a subtree keeps going for as long as each package resolves —
// Parent -> Child -> Grandchild here. Lookup is by name alone, which is
// snyk-nuget-plugin's behavior.
func TestBuildFrameworkDepGraph_ChildrenAreLookedUpByName(t *testing.T) {
	graph := buildFramework(t,
		[]declaredPackage{{"Parent", "1.0.0"}, {"Child", "2.0.0"}},
		map[string][]declaredPackage{
			"Parent": {{"Child", "2.0.0"}},
			"Child":  {{"Grandchild", "3.0.0"}},
		})

	assert.Equal(t, []string{"Child@2.0.0"}, depsOf(t, graph, "Parent@1.0.0"))
	assert.Equal(t, []string{"Grandchild@3.0.0"}, depsOf(t, graph, "Child@2.0.0"))
}

func TestBuildFrameworkDepGraph_HonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	installed := newPackageSet()
	installed.add("A", "1.0.0")

	_, err := buildFrameworkDepGraph(ctx, "App", defaultVersion, installed,
		map[string][]declaredPackage{"A": {{"B", "1.0.0"}}})

	require.ErrorIs(t, err, context.Canceled)
}

// A chain of shared dependencies, which is what a real packages folder looks
// like. Every level is reachable by two routes, so re-walking each one would
// cost 2^depth: this test finishes instantly while the walk stays linear, and
// times the package out if that guard ever goes.
func TestBuildFrameworkDepGraph_SharedSubtreesAreWalkedOnce(t *testing.T) {
	const depth = 40

	declared := make([]declaredPackage, 0, depth)
	children := map[string][]declaredPackage{}

	for level := range depth {
		name := fmt.Sprintf("Level%02d", level)
		declared = append(declared, declaredPackage{name, "1.0.0"})

		if level+1 < depth {
			next := declaredPackage{fmt.Sprintf("Level%02d", level+1), "1.0.0"}
			// Two routes to the same child, so a resolver that forgets what it
			// has already walked doubles its work at every level.
			children[name] = []declaredPackage{next, next}
		}
	}

	graph := buildFramework(t, declared, children)
	assert.Len(t, graph.Pkgs, depth+1, "one node per level, plus the root")
}
