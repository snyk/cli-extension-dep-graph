package nuget

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
)

// buildFramework builds a graph the way emitFrameworkResult does, from a
// declared package list.
func buildFramework(t *testing.T, declared []declaredPackage) *godepgraph.DepGraph {
	t.Helper()

	installed := newPackageSet()
	for _, pkg := range declared {
		installed.add(pkg.name, pkg.version)
	}

	graph, err := buildFrameworkDepGraph("App", defaultVersion, installed)
	require.NoError(t, err)

	return graph
}

func TestBuildFrameworkDepGraph_RootPackage(t *testing.T) {
	graph, err := buildFrameworkDepGraph("MyApp", "4.5.6", newPackageSet())
	require.NoError(t, err)

	assert.Equal(t, pkgManager, graph.PkgManager.Name)
	assert.Equal(t, "MyApp", graph.GetRootPkg().Info.Name)
	assert.Equal(t, "4.5.6", graph.GetRootPkg().Info.Version)
	assert.Equal(t, []string{"MyApp@4.5.6"}, pkgIDs(graph.Pkgs), "a project with nothing installed is root-only")
}

// Every package hangs off the root, whether the project asked for it or one of
// its dependencies did. A .NET Framework manifest is a flattened list with no
// record of who pulled what in, so there is nothing else to go on.
func TestBuildFrameworkDepGraph_EveryPackageIsDirect(t *testing.T) {
	graph := buildFramework(t, []declaredPackage{
		{"jQuery", "3.2.1"},
		{"Moment.js", "2.20.1"},
		{"Newtonsoft.Json", "10.0.3"},
	})

	assert.ElementsMatch(t,
		[]string{"App@0.0.0", "jQuery@3.2.1", "Moment.js@2.20.1", "Newtonsoft.Json@10.0.3"},
		pkgIDs(graph.Pkgs))

	assert.Equal(t,
		[]string{"Moment.js@2.20.1", "Newtonsoft.Json@10.0.3", "jQuery@3.2.1"},
		depsOf(t, graph, graph.Graph.RootNodeID))
}

// A repeated name is one package, at the version first declared for it.
func TestBuildFrameworkDepGraph_RepeatedNameIsOnePackage(t *testing.T) {
	graph := buildFramework(t, []declaredPackage{{"jQuery", "1.9.1"}, {"jQuery", "3.2.1"}})

	assert.ElementsMatch(t, []string{"App@0.0.0", "jQuery@1.9.1"}, pkgIDs(graph.Pkgs))
	assert.Equal(t, []string{"jQuery@1.9.1"}, depsOf(t, graph, graph.Graph.RootNodeID))
}
