package bun

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDepGraph_Simple(t *testing.T) {
	graph := &whyGraph{
		Packages: pkgRegistry{
			"debug": "4.4.3",
			"ms":    "2.1.3",
		},
		Dependencies: depEdges{
			{Name: "debug", Version: "4.4.3"}: pkgSet{{Name: "ms", Version: "2.1.3"}: {}},
		},
	}

	seeds := map[pkgName]struct{}{"debug": struct{}{}}

	dg, err := buildDepGraph("my-app", "1.0.0", seeds, graph)
	require.NoError(t, err)
	require.NotNil(t, dg)

	assert.Equal(t, "bun", dg.PkgManager.Name)
	assert.Equal(t, "my-app", dg.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", dg.GetRootPkg().Info.Version)

	pkgIDs := make(map[string]bool)
	for _, p := range dg.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])
}

func TestBuildDepGraph_ExcludesDevDepsWhenNotRequested(t *testing.T) {
	// dev dep @types/bun is NOT in seeds when includeDev=false.
	graph := &whyGraph{
		Packages: pkgRegistry{
			"debug":      "4.4.3",
			"ms":         "2.1.3",
			"@types/bun": "1.3.11",
		},
		Dependencies: depEdges{
			{Name: "debug", Version: "4.4.3"}: pkgSet{{Name: "ms", Version: "2.1.3"}: {}},
		},
	}

	// Production seeds only.
	seeds := map[pkgName]struct{}{"debug": struct{}{}}

	dg, err := buildDepGraph("my-app", "1.0.0", seeds, graph)
	require.NoError(t, err)

	pkgIDs := make(map[string]bool)
	for _, p := range dg.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])
	assert.False(t, pkgIDs["@types/bun@1.3.11"], "dev dep should be excluded")
}

func TestBuildDepGraph_WorkspaceMegaGraph(t *testing.T) {
	// Simulates: root → @workspace/logger → axios → follow-redirects
	//            root → debug → ms
	graph := &whyGraph{
		Packages: pkgRegistry{
			"@workspace/logger": "workspace:packages/logger",
			"axios":             "1.14.0",
			"follow-redirects":  "1.15.9",
			"debug":             "4.4.3",
			"ms":                "2.1.3",
		},
		Dependencies: depEdges{
			{Name: "@workspace/logger", Version: "workspace:packages/logger"}: pkgSet{{Name: "axios", Version: "1.14.0"}: {}},
			{Name: "axios", Version: "1.14.0"}:                                pkgSet{{Name: "follow-redirects", Version: "1.15.9"}: {}},
			{Name: "debug", Version: "4.4.3"}:                                 pkgSet{{Name: "ms", Version: "2.1.3"}: {}},
		},
	}

	seeds := map[pkgName]struct{}{
		"@workspace/logger": struct{}{},
		"debug":             struct{}{},
	}

	dg, err := buildDepGraph("my-workspace", "1.0.0", seeds, graph)
	require.NoError(t, err)
	require.NotNil(t, dg)

	pkgIDs := make(map[string]bool)
	for _, p := range dg.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["@workspace/logger@workspace:packages/logger"])
	assert.True(t, pkgIDs["axios@1.14.0"])
	assert.True(t, pkgIDs["follow-redirects@1.15.9"])
	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])
}

func TestBuildDepGraph_SkipsMissingPackages(t *testing.T) {
	// Seeds include a package not in Packages (e.g. a workspace: ref).
	graph := &whyGraph{
		Packages:     pkgRegistry{"debug": "4.4.3"},
		Dependencies: depEdges{},
	}

	seeds := map[pkgName]struct{}{
		"debug":   struct{}{},
		"missing": struct{}{}, // not in Packages
	}

	dg, err := buildDepGraph("my-app", "1.0.0", seeds, graph)
	require.NoError(t, err)
	require.NotNil(t, dg)

	pkgIDs := make(map[string]bool)
	for _, p := range dg.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.False(t, pkgIDs["missing@"])
}

func TestBuildDepGraph_HandlesCircularDeps(t *testing.T) {
	// a depends on b, b depends on a.
	graph := &whyGraph{
		Packages: pkgRegistry{
			"pkg-a": "1.0.0",
			"pkg-b": "2.0.0",
		},
		Dependencies: depEdges{
			{Name: "pkg-a", Version: "1.0.0"}: pkgSet{{Name: "pkg-b", Version: "2.0.0"}: {}},
			{Name: "pkg-b", Version: "2.0.0"}: pkgSet{{Name: "pkg-a", Version: "1.0.0"}: {}},
		},
	}

	seeds := map[pkgName]struct{}{"pkg-a": struct{}{}}

	// Should not infinite-loop.
	dg, err := buildDepGraph("root", "0.0.0", seeds, graph)
	require.NoError(t, err)
	require.NotNil(t, dg)
}
