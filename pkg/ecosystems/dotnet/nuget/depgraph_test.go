package nuget

import (
	"context"
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// detailOf returns the Detail of an error-catalog error.
//
// Error() only yields the catalog entry's title, and Detail is the part the
// dep-graph workflow actually shows the user — so it is the part worth
// asserting on.
func detailOf(t *testing.T, err error) string {
	t.Helper()

	var snykErr snyk_errors.Error
	require.ErrorAs(t, err, &snykErr, "errors reaching the user must come from the error catalog")

	return snykErr.Detail
}

// assetsFrom parses an assets file from a literal, so a test can state exactly
// the shape it is about.
func assetsFrom(t *testing.T, content string) *projectAssets {
	t.Helper()

	var assets projectAssets
	require.NoError(t, json.Unmarshal([]byte(content), &assets))

	return &assets
}

// pkgIDs lists the package IDs in a graph.
func pkgIDs(pkgs []godepgraph.Pkg) []string {
	ids := make([]string, len(pkgs))
	for i, pkg := range pkgs {
		ids[i] = pkg.ID
	}

	return ids
}

// depsOf returns the sorted node IDs a node depends on.
func depsOf(t *testing.T, graph *godepgraph.DepGraph, nodeID string) []string {
	t.Helper()

	for _, node := range graph.Graph.Nodes {
		if node.NodeID != nodeID {
			continue
		}

		deps := make([]string, len(node.Deps))
		for i, dep := range node.Deps {
			deps[i] = dep.NodeID
		}
		sort.Strings(deps)

		return deps
	}

	t.Fatalf("no node %q in the graph", nodeID)

	return nil
}

// nodeByID finds a node, failing the test when it is absent.
func nodeByID(t *testing.T, graph *godepgraph.DepGraph, nodeID string) godepgraph.Node {
	t.Helper()

	for _, node := range graph.Graph.Nodes {
		if node.NodeID == nodeID {
			return node
		}
	}

	t.Fatalf("no node %q in the graph", nodeID)

	return godepgraph.Node{}
}

// build resolves the sole target framework of an assets literal.
func build(t *testing.T, content string) *godepgraph.DepGraph {
	t.Helper()

	assets := assetsFrom(t, content)
	require.Len(t, assets.targetFrameworks(), 1, "this helper is for single-framework fixtures")

	framework := assets.targetFrameworks()[0]

	graph, err := buildDepGraph(t.Context(), assets, "RootProject", assets.matchTargetsKey(framework))
	require.NoError(t, err)

	return graph
}

func TestBuildDepGraph_RootPackage(t *testing.T) {
	graph := build(t, `{
      "targets": { "net8.0": {} },
      "project": { "version": "4.5.6", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, pkgManager, graph.PkgManager.Name)
	assert.Equal(t, "RootProject", graph.GetRootPkg().Info.Name)
	assert.Equal(t, "4.5.6", graph.GetRootPkg().Info.Version)
	assert.Equal(t, []string{"RootProject@4.5.6"}, pkgIDs(graph.Pkgs))
	assert.Empty(t, depsOf(t, graph, graph.Graph.RootNodeID))
}

// project.version is optional. snyk-nuget-plugin roots such a project at 0.0.0.
func TestBuildDepGraph_RootVersionFallsBackToDefault(t *testing.T) {
	graph := build(t, `{
      "targets": { "net8.0": {} },
      "project": { "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, defaultVersion, graph.GetRootPkg().Info.Version)
}

// A project with no projectFileDependencyGroups at all is legitimate — it just
// has no direct dependencies — and must not be mistaken for a failed restore.
func TestBuildDepGraph_NoDirectDependencies(t *testing.T) {
	graph := build(t, `{
      "targets": { "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } } },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Len(t, graph.Pkgs, 1, "a package nobody depends on is not in the graph")
	assert.Empty(t, depsOf(t, graph, graph.Graph.RootNodeID))
}

func TestBuildDepGraph_DirectAndTransitive(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "Top/1.0.0": { "type": "package", "dependencies": { "Middle": "2.0.0" } },
          "Middle/2.0.0": { "type": "package", "dependencies": { "Bottom": "3.0.0" } },
          "Bottom/3.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Top >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Top@1.0.0"}, depsOf(t, graph, graph.Graph.RootNodeID))
	assert.Equal(t, []string{"Middle@2.0.0"}, depsOf(t, graph, "Top@1.0.0"))
	assert.Equal(t, []string{"Bottom@3.0.0"}, depsOf(t, graph, "Middle@2.0.0"))
	assert.Empty(t, depsOf(t, graph, "Bottom@3.0.0"))
}

// The version a parent declares is a minimum constraint, not a resolution. Only
// the `targets` key says what the project actually restored — this is how
// transitive pinning and central package management show up correctly.
func TestBuildDepGraph_ResolvedVersionWinsOverDeclaredMinimum(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "Azure.Identity/1.10.4": { "type": "package", "dependencies": { "Azure.Core": "1.0.0" } },
          "Azure.Core/1.35.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Azure.Identity >= 1.7.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Azure.Identity@1.10.4"}, depsOf(t, graph, graph.Graph.RootNodeID))
	assert.Equal(t, []string{"Azure.Core@1.35.0"}, depsOf(t, graph, "Azure.Identity@1.10.4"))
	assert.NotContains(t, pkgIDs(graph.Pkgs), "Azure.Core@1.0.0")
	assert.NotContains(t, pkgIDs(graph.Pkgs), "Azure.Identity@1.7.0")
}

// NuGet names are case-insensitive and the assets file is inconsistent between
// sections, so lookups ignore case while the reported name comes from the
// `targets` key.
func TestBuildDepGraph_CaseInsensitiveLookupReportsTargetsCasing(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "DotNetNuke.Core/7.0.0": { "type": "package", "dependencies": { "NEWTONSOFT.JSON": "13.0.3" } },
          "Newtonsoft.Json/13.0.3": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "dotnetnuke.core >= 7.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"DotNetNuke.Core@7.0.0"}, depsOf(t, graph, graph.Graph.RootNodeID))
	assert.Equal(t, []string{"Newtonsoft.Json@13.0.3"}, depsOf(t, graph, "DotNetNuke.Core@7.0.0"))
}

// runtime* packages describe platform-specific assets rather than anything a
// user can act on, so they are dropped — both as direct and as transitive deps.
func TestBuildDepGraph_FiltersRuntimePackages(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "Top/1.0.0": { "type": "package", "dependencies": { "runtime.native.System.Foo": "4.3.0" } },
          "runtime.native.System.Foo/4.3.0": { "type": "package" },
          "runtime/1.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Top >= 1.0.0", "runtime >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Top@1.0.0"}, depsOf(t, graph, graph.Graph.RootNodeID))
	assert.Empty(t, depsOf(t, graph, "Top@1.0.0"))
	assert.Equal(t, []string{"RootProject@1.0.0", "Top@1.0.0"}, pkgIDs(graph.Pkgs))
}

// A direct dependency with no entry in `targets` is expected rather than broken:
// framework references such as Microsoft.NETCore.App are declared by the project
// and never resolved as packages.
func TestBuildDepGraph_SkipsUnresolvableDependencies(t *testing.T) {
	graph := build(t, `{
      "targets": { "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } } },
      "projectFileDependencyGroups": {
        "net8.0": [ "Microsoft.NETCore.App >= 8.0.0", "Newtonsoft.Json >= 13.0.3" ]
      },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Newtonsoft.Json@13.0.3"}, depsOf(t, graph, graph.Graph.RootNodeID))
}

// A shared dependency is one node with two parents, and each edge is recorded
// once — the builder appends without deduplicating, and the traversal reaches a
// shared subtree once per path into it.
func TestBuildDepGraph_DiamondSharesOneNode(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "Left/1.0.0": { "type": "package", "dependencies": { "Shared": "1.0.0" } },
          "Right/1.0.0": { "type": "package", "dependencies": { "Shared": "1.0.0" } },
          "Shared/2.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Left >= 1.0.0", "Right >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Left@1.0.0", "Right@1.0.0"}, depsOf(t, graph, graph.Graph.RootNodeID))
	assert.Equal(t, []string{"Shared@2.0.0"}, depsOf(t, graph, "Left@1.0.0"))
	assert.Equal(t, []string{"Shared@2.0.0"}, depsOf(t, graph, "Right@1.0.0"))
	assert.Len(t, graph.Graph.Nodes, 4, "Shared appears once")
}

// The visited set is copied on entry to every call, so what one sibling's
// subtree adds is invisible to the next sibling. Only a package on the current
// path — or one an earlier sibling took directly — is pruned.
//
// This is the shape that looks like it should break: Shared sits two levels
// under Left, and is also a direct dependency of Right. If subtree additions
// leaked between siblings, Right -> Shared would come out pruned.
func TestBuildDepGraph_SiblingSubtreesDoNotPruneEachOther(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "Left/1.0.0": { "type": "package", "dependencies": { "Middle": "1.0.0" } },
          "Middle/1.0.0": { "type": "package", "dependencies": { "Shared": "1.0.0" } },
          "Right/1.0.0": { "type": "package", "dependencies": { "Shared": "1.0.0" } },
          "Shared/2.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Left >= 1.0.0", "Right >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Shared@2.0.0"}, depsOf(t, graph, "Middle@1.0.0"))
	assert.Equal(t, []string{"Shared@2.0.0"}, depsOf(t, graph, "Right@1.0.0"),
		"a real edge, not Shared@2.0.0:pruned")

	for _, node := range graph.Graph.Nodes {
		assert.NotContains(t, node.NodeID, prunedNodeSuffix, "nothing here is a cycle")
	}

	assert.Len(t, graph.Graph.Nodes, 5, "root, Left, Middle, Right, Shared")
}

// A cycle terminates in a childless node marked pruned, matching the
// `<id>:pruned` leaves snyk-nuget-plugin emits.
func TestBuildDepGraph_CycleYieldsPrunedLeaf(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "Top/1.0.0": { "type": "package", "dependencies": { "Loop": "1.0.0" } },
          "Loop/1.0.0": { "type": "package", "dependencies": { "Top": "1.0.0" } }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Top >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Loop@1.0.0"}, depsOf(t, graph, "Top@1.0.0"))
	assert.Equal(t, []string{"Top@1.0.0" + prunedNodeSuffix}, depsOf(t, graph, "Loop@1.0.0"))

	pruned := nodeByID(t, graph, "Top@1.0.0"+prunedNodeSuffix)
	assert.Empty(t, pruned.Deps, "a pruned node terminates the walk")
	assert.Equal(t, "Top@1.0.0", pruned.PkgID, "it is the same package, not a new one")
	require.NotNil(t, pruned.Info)
	assert.Equal(t, map[string]string{prunedLabelKey: prunedLabelValue}, pruned.Info.Labels)

	// The pruned node shares a package with the real one, so no extra package.
	assert.ElementsMatch(t, []string{"RootProject@1.0.0", "Top@1.0.0", "Loop@1.0.0"}, pkgIDs(graph.Pkgs))
}

// A ProjectReference appears in `targets` as type "project". Upstream never
// inspects the type, so it becomes an ordinary node named after the project.
func TestBuildDepGraph_ProjectReferenceIsAnOrdinaryNode(t *testing.T) {
	graph := build(t, `{
      "targets": {
        "net8.0": {
          "Referenced/1.0.0": {
            "type": "project",
            "dependencies": { "Newtonsoft.Json": "13.0.3" }
          },
          "Newtonsoft.Json/13.0.3": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Referenced >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Referenced@1.0.0"}, depsOf(t, graph, graph.Graph.RootNodeID))
	assert.Equal(t, []string{"Newtonsoft.Json@13.0.3"}, depsOf(t, graph, "Referenced@1.0.0"))
}

// A shared subtree is re-walked once per path that reaches it, matching
// upstream, so the traversal can run long on a pathological file. Cancellation
// is the caller's way out of it.
func TestBuildDepGraph_HonoursCancellation(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": {
        "net8.0": {
          "Top/1.0.0": { "type": "package", "dependencies": { "Leaf": "1.0.0" } },
          "Leaf/1.0.0": { "type": "package" }
        }
      },
      "projectFileDependencyGroups": { "net8.0": [ "Top >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := buildDepGraph(ctx, assets, "RootProject", "net8.0")
	require.ErrorIs(t, err, context.Canceled)
}

func TestBuildDepGraph_UnknownTargetsKey(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": { "net8.0": {} },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	_, err := buildDepGraph(t.Context(), assets, "RootProject", "net9.0")
	require.ErrorIs(t, err, errNoResolvedPackages)
	assert.Contains(t, err.Error(), "net9.0")
}

// A target section that is present but carries nothing, while the project
// declares dependencies, is a restore that did not finish. The root-only graph
// that falls out of it would tell the user the project has no dependencies.
func TestBuildDepGraph_DeclaredDependenciesButNoPackages(t *testing.T) {
	for name, targets := range map[string]string{
		"null section":  `{"net8.0": null}`,
		"empty section": `{"net8.0": {}}`,
	} {
		t.Run(name, func(t *testing.T) {
			assets := assetsFrom(t, `{
              "targets": `+targets+`,
              "projectFileDependencyGroups": { "net8.0": [ "Newtonsoft.Json >= 13.0.3" ] },
              "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
            }`)

			_, err := buildDepGraph(t.Context(), assets, "RootProject", "net8.0")
			require.ErrorIs(t, err, errNoResolvedPackages)
		})
	}
}

// A project that declares nothing is still legitimate, so an empty target
// section on its own is not an error.
func TestBuildDepGraph_NoDependenciesDeclaredOrResolved(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": { "net8.0": {} },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	graph, err := buildDepGraph(t.Context(), assets, "RootProject", "net8.0")
	require.NoError(t, err)
	assert.Len(t, graph.Pkgs, 1)
}

// Upstream collapses a repeated direct dependency into one entry; keeping both
// would walk the package a second time and hang a pruned leaf off the root.
func TestBuildDepGraph_RepeatedDirectDependency(t *testing.T) {
	graph := build(t, `{
      "targets": { "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } } },
      "projectFileDependencyGroups": {
        "net8.0": [ "Newtonsoft.Json >= 13.0.3", "Newtonsoft.Json >= 13.0.3" ]
      },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	assert.Equal(t, []string{"Newtonsoft.Json@13.0.3"}, depsOf(t, graph, graph.Graph.RootNodeID),
		"no second edge, and no pruned leaf")
	assert.Len(t, graph.Graph.Nodes, 2)
}
