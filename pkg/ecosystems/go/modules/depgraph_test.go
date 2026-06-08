package modules

import (
	"strings"
	"testing"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nodeDeps returns the NodeIDs of the direct dependencies of node
// nodeID in dg. Returns nil if the node doesn't exist.
func nodeDeps(dg *godepgraph.DepGraph, nodeID string) []string {
	for _, n := range dg.Graph.Nodes {
		if n.NodeID != nodeID {
			continue
		}
		out := make([]string, len(n.Deps))
		for i, d := range n.Deps {
			out[i] = d.NodeID
		}
		return out
	}
	return nil
}

// pkgIDs returns the set of pkg IDs (name@version) present in dg.
func pkgIDs(dg *godepgraph.DepGraph) map[string]bool {
	out := make(map[string]bool, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		out[p.ID] = true
	}
	return out
}

// findPkg returns the Pkg with the given ID, failing the test if missing.
func findPkg(t *testing.T, dg *godepgraph.DepGraph, id string) godepgraph.Pkg {
	t.Helper()
	for _, p := range dg.Pkgs {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("pkg %q not in graph (have: %v)", id, pkgIDs(dg))
	return godepgraph.Pkg{}
}

func TestToSnykVersion(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"v1.2.3", "1.2.3"},
		{"v1.2.3+incompatible", "1.2.3"},
		{"v0.0.0-20240101120000-abcdef012345", "#abcdef012345"},
		{"v1.2.3-beta.1.20240101120000-abcdef012345", "#abcdef012345"},
		{"1.2.3", "1.2.3"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, toSnykVersion(tt.in))
		})
	}
}

func TestParseGoListOutput_ConcatenatedObjects(t *testing.T) {
	// `go list -json` emits each package as a separate JSON object,
	// NOT a JSON array.
	raw := `{"ImportPath":"a"}
{"ImportPath":"b","Standard":true}
{"ImportPath":"c"}
`
	pkgs, err := parseGoListOutput(strings.NewReader(raw))
	require.NoError(t, err)
	require.Len(t, pkgs, 3)
	assert.Equal(t, "a", pkgs[0].ImportPath)
	assert.Equal(t, "b", pkgs[1].ImportPath)
	assert.True(t, pkgs[1].Standard)
	assert.Equal(t, "c", pkgs[2].ImportPath)
}

func TestParseGoListOutput_Empty(t *testing.T) {
	pkgs, err := parseGoListOutput(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, pkgs)
}

func TestParseGoListOutput_Malformed(t *testing.T) {
	_, err := parseGoListOutput(strings.NewReader("{not-json}"))
	assert.Error(t, err)
}

func TestBuildDepGraph_Simple(t *testing.T) {
	// Root module example.com/app with one local pkg importing one
	// external module github.com/lib/foo@v1.0.0.
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"github.com/lib/foo"},
		},
		{
			ImportPath: "github.com/lib/foo",
			DepOnly:    true,
			Module:     &GoModule{Path: "github.com/lib/foo", Version: "v1.0.0"},
		},
	}

	dg, err := buildDepGraph(pkgs, "fallback", GraphOptions{})
	require.NoError(t, err)

	assert.Equal(t, "gomodules", dg.PkgManager.Name)
	assert.Equal(t, "example.com/app", dg.GetRootPkg().Info.Name)

	ids := pkgIDs(dg)
	assert.True(t, ids["github.com/lib/foo@1.0.0"], "foo at 1.0.0 (v stripped)")
	assert.Contains(t, nodeDeps(dg, "root-node"), "github.com/lib/foo")
}

func TestBuildDepGraph_FallbackRoot(t *testing.T) {
	// No package with Main=true → uses fallback name.
	pkgs := []GoListPackage{
		{ImportPath: "github.com/lib/foo", DepOnly: true,
			Module: &GoModule{Path: "github.com/lib/foo", Version: "v1.0.0"}},
	}
	dg, err := buildDepGraph(pkgs, "myapp", GraphOptions{})
	require.NoError(t, err)
	assert.Equal(t, "myapp", dg.GetRootPkg().Info.Name)
}

func TestBuildDepGraph_ReplaceDirective_UseReplaceNameTrue(t *testing.T) {
	// Top-level imports github.com/old/lib which is replaced with
	// github.com/new/lib at a new version.
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"github.com/old/lib"},
		},
		{
			ImportPath: "github.com/old/lib",
			DepOnly:    true,
			Module: &GoModule{
				Path:    "github.com/old/lib",
				Version: "v1.0.0",
				Replace: &GoModule{Path: "github.com/new/lib", Version: "v2.0.0"},
			},
		},
	}

	dg, err := buildDepGraph(pkgs, "x", GraphOptions{UseReplaceName: true})
	require.NoError(t, err)

	ids := pkgIDs(dg)
	assert.True(t, ids["github.com/new/lib@2.0.0"], "replace name swapped")
	assert.False(t, ids["github.com/old/lib@2.0.0"], "original name dropped")
}

func TestBuildDepGraph_ReplaceDirective_UseReplaceNameFalse(t *testing.T) {
	// Same input as above; with UseReplaceName off the original name
	// is retained but the replacement version is still applied.
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"github.com/old/lib"},
		},
		{
			ImportPath: "github.com/old/lib",
			DepOnly:    true,
			Module: &GoModule{
				Path:    "github.com/old/lib",
				Version: "v1.0.0",
				Replace: &GoModule{Path: "github.com/new/lib", Version: "v2.0.0"},
			},
		},
	}

	dg, err := buildDepGraph(pkgs, "x", GraphOptions{UseReplaceName: false})
	require.NoError(t, err)

	ids := pkgIDs(dg)
	assert.True(t, ids["github.com/old/lib@2.0.0"], "name kept, version from Replace")
}

func TestBuildDepGraph_StdlibFiltered_ByDefault(t *testing.T) {
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"fmt", "github.com/lib/foo"},
		},
		{ImportPath: "fmt", Standard: true},
		{
			ImportPath: "github.com/lib/foo",
			DepOnly:    true,
			Module:     &GoModule{Path: "github.com/lib/foo", Version: "v1.0.0"},
		},
	}

	dg, err := buildDepGraph(pkgs, "x", GraphOptions{})
	require.NoError(t, err)

	ids := pkgIDs(dg)
	assert.False(t, ids["std/fmt@unknown"], "stdlib dropped by default")
	assert.True(t, ids["github.com/lib/foo@1.0.0"])
}

func TestBuildDepGraph_StdlibIncluded(t *testing.T) {
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"fmt"},
		},
		{ImportPath: "fmt", Standard: true},
	}

	dg, err := buildDepGraph(pkgs, "x", GraphOptions{IncludeStdlib: true, StdlibVersion: "1.21.0"})
	require.NoError(t, err)

	stdPkg := findPkg(t, dg, "std/fmt@1.21.0")
	assert.Equal(t, "std/fmt", stdPkg.Info.Name)
	assert.Equal(t, "1.21.0", stdPkg.Info.Version)
	assert.Contains(t, nodeDeps(dg, "root-node"), "std/fmt")
}

func TestBuildDepGraph_StdlibIncluded_DefaultUnknownVersion(t *testing.T) {
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"fmt"},
		},
		{ImportPath: "fmt", Standard: true},
	}

	dg, err := buildDepGraph(pkgs, "x", GraphOptions{IncludeStdlib: true})
	require.NoError(t, err)
	assert.True(t, pkgIDs(dg)["std/fmt@unknown"], "default stdlib version is 'unknown'")
}

func TestBuildDepGraph_Cycle_SelfImport(t *testing.T) {
	// Pathological: a@1.0.0 lists itself as an import. The legacy
	// cycle-break drops the self-edge silently.
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"github.com/a"},
		},
		{
			ImportPath: "github.com/a",
			DepOnly:    true,
			Module:     &GoModule{Path: "github.com/a", Version: "v1.0.0"},
			Imports:    []string{"github.com/a"},
		},
	}

	dg, err := buildDepGraph(pkgs, "x", GraphOptions{})
	require.NoError(t, err)

	// 'a' present, but no self-edge.
	assert.True(t, pkgIDs(dg)["github.com/a@1.0.0"])
	assert.NotContains(t, nodeDeps(dg, "github.com/a"), "github.com/a")
}

func TestBuildDepGraph_Cycle_TwoNode(t *testing.T) {
	// a → b → a — the cycle survives the build (no infinite recursion,
	// no error) and both nodes appear. The legacy plugin's heuristic
	// breaks the cycle on the inner-most descent: once a is a known
	// ancestor of b, the b→a back-edge is dropped. Top-level seeding
	// order can re-introduce the edge from a different path, so we
	// assert only that the build completes and both nodes are present.
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"github.com/a"},
		},
		{
			ImportPath: "github.com/a", DepOnly: true,
			Module:  &GoModule{Path: "github.com/a", Version: "v1.0.0"},
			Imports: []string{"github.com/b"},
		},
		{
			ImportPath: "github.com/b", DepOnly: true,
			Module:  &GoModule{Path: "github.com/b", Version: "v1.0.0"},
			Imports: []string{"github.com/a"},
		},
	}

	dg, err := buildDepGraph(pkgs, "x", GraphOptions{})
	require.NoError(t, err, "build completes without stack overflow")

	assert.True(t, pkgIDs(dg)["github.com/a@1.0.0"])
	assert.True(t, pkgIDs(dg)["github.com/b@1.0.0"])
}

func TestBuildDepGraph_PseudoVersion(t *testing.T) {
	pkgs := []GoListPackage{
		{
			ImportPath: "example.com/app",
			Module:     &GoModule{Path: "example.com/app", Main: true},
			Imports:    []string{"github.com/lib/foo"},
		},
		{
			ImportPath: "github.com/lib/foo", DepOnly: true,
			Module: &GoModule{Path: "github.com/lib/foo", Version: "v0.0.0-20240101120000-abcdef012345"},
		},
	}
	dg, err := buildDepGraph(pkgs, "x", GraphOptions{})
	require.NoError(t, err)
	assert.True(t, pkgIDs(dg)["github.com/lib/foo@#abcdef012345"], "pseudo-version → #short-sha")
}

func TestBuildDepGraph_EmptyInput(t *testing.T) {
	dg, err := buildDepGraph(nil, "myapp", GraphOptions{})
	require.NoError(t, err)
	assert.Equal(t, "myapp", dg.GetRootPkg().Info.Name)
	// Only the root node should exist.
	assert.Len(t, dg.Graph.Nodes, 1)
}

func TestExtractTopLevelImports_Dedup(t *testing.T) {
	pkgs := []GoListPackage{
		{ImportPath: "a", Imports: []string{"x", "y"}},
		{ImportPath: "b", Imports: []string{"y", "z"}},
	}
	got := extractTopLevelImports(pkgs)
	assert.ElementsMatch(t, []string{"x", "y", "z"}, got)
}
