package bun_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/internal/bun"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
)

var testLogger = logger.Nop()

func TestBunPlugin_SingleProject(t *testing.T) {
	plugin := bun.NewBunPlugin()

	findings, err := plugin.BuildFindingsFromDir(
		context.Background(),
		"testdata/simple",
		&scaplugin.Options{},
		testLogger,
	)

	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Nil(t, f.Error)
	assert.Equal(t, "bun.lock", f.LockFile)
	assert.Equal(t, "package.json", f.ManifestFile)
	require.NotNil(t, f.DepGraph)

	rootPkg := f.DepGraph.GetRootPkg()
	require.NotNil(t, rootPkg)
	assert.Equal(t, "my-app", rootPkg.Info.Name)

	pkgNames := allPkgNames(f)
	// direct + transitive production deps
	assert.Contains(t, pkgNames, "express")
	assert.Contains(t, pkgNames, "accepts")
	assert.Contains(t, pkgNames, "ms")
	// devDep should NOT appear without --dev
	assert.NotContains(t, pkgNames, "typescript")
}

func TestBunPlugin_SingleProject_WithDev(t *testing.T) {
	plugin := bun.NewBunPlugin()

	findings, err := plugin.BuildFindingsFromDir(
		context.Background(),
		"testdata/simple",
		&scaplugin.Options{Dev: true},
		testLogger,
	)

	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, allPkgNames(findings[0]), "typescript")
}

func TestBunPlugin_SkipsNonBunTargetFile(t *testing.T) {
	plugin := bun.NewBunPlugin()

	findings, err := plugin.BuildFindingsFromDir(
		context.Background(),
		"testdata/simple",
		&scaplugin.Options{TargetFile: "package-lock.json"},
		testLogger,
	)

	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestBunPlugin_Workspaces(t *testing.T) {
	plugin := bun.NewBunPlugin()

	findings, err := plugin.BuildFindingsFromDir(
		context.Background(),
		"testdata/workspace",
		&scaplugin.Options{AllProjects: true},
		testLogger,
	)

	require.NoError(t, err)
	require.Len(t, findings, 3, "expected one finding per workspace")

	for _, f := range findings {
		require.Nil(t, f.Error)
		require.NotNil(t, f.DepGraph)
	}

	rootNames := make([]string, 0, len(findings))
	for _, f := range findings {
		rootNames = append(rootNames, f.DepGraph.GetRootPkg().Info.Name)
	}
	assert.ElementsMatch(t, []string{"my-monorepo", "server", "client"}, rootNames)
}

func TestBunPlugin_WorkspaceProtocol_Filtered(t *testing.T) {
	plugin := bun.NewBunPlugin()

	findings, err := plugin.BuildFindingsFromDir(
		context.Background(),
		"testdata/workspace",
		&scaplugin.Options{AllProjects: true},
		testLogger,
	)

	require.NoError(t, err)

	for _, f := range findings {
		if f.DepGraph.GetRootPkg().Info.Name == "server" {
			// workspace: protocol dep should be filtered — not cause an error
			assert.NotContains(t, allPkgNames(f), "server-lib")
			return
		}
	}
	t.Fatal("server workspace not found in findings")
}

// allPkgNames returns all non-root package names in the dep graph.
func allPkgNames(f scaplugin.Finding) []string {
	names := make([]string, 0, len(f.DepGraph.Pkgs))
	rootPkg := f.DepGraph.GetRootPkg()
	for _, pkg := range f.DepGraph.Pkgs {
		if rootPkg != nil && pkg.Info.Name == rootPkg.Info.Name && pkg.Info.Version == rootPkg.Info.Version {
			continue
		}
		names = append(names, pkg.Info.Name)
	}
	return names
}
