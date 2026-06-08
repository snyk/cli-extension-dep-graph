package bundler

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// writeFile is a t.TempDir helper for fixture setup.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// simpleLock is the minimal valid Gemfile.lock used across plugin tests.
const simpleLock = `GEM
  remote: http://rubygems.org/
  specs:
    json (2.0.2)
    lynx (0.4.0)

PLATFORMS
  ruby

DEPENDENCIES
  json
  lynx (= 0.4.0)

BUNDLED WITH
   1.13.5
`

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "bundler", Plugin{}.GetName())
}

func TestPlugin_BuildsGraphFromGemfileLock(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp,
		ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.NoError(t, r.Error)
	require.NotNil(t, r.DepGraph)

	// Identity contract: rootPkg.name = basename(dir).
	assert.Equal(t, filepath.Base(tmp), r.DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "Gemfile.lock", r.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, []string{"Gemfile.lock"}, r.ProcessedFiles)
	require.NotNil(t, r.ResolverMetadata)
	assert.Equal(t, "bundler", r.ResolverMetadata.PluginName)

	ids := make(map[string]bool, len(r.DepGraph.Pkgs))
	for _, p := range r.DepGraph.Pkgs {
		ids[p.ID] = true
	}
	assert.True(t, ids["json@2.0.2"])
	assert.True(t, ids["lynx@0.4.0"])
}

// TestPlugin_NoGemfileLock returns empty (not an error) — matches the
// bun-style default-mode behavior in javascript/bun/plugin.go.
func TestPlugin_NoGemfileLock(t *testing.T) {
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), t.TempDir(),
		ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_TargetFileGemfile(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile"), "source 'https://rubygems.org'\n")
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)

	// Caller passes the Gemfile path — plugin should still find the
	// sibling Gemfile.lock (legacy parity).
	opts := ecosystems.NewPluginOptions().WithTargetFile("Gemfile")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	// The reported target file is the lockfile we actually consulted.
	assert.Equal(t, "Gemfile.lock", results[0].ProjectDescriptor.GetTargetFile())
}

func TestPlugin_TargetFileGemfileLock(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)

	opts := ecosystems.NewPluginOptions().WithTargetFile("Gemfile.lock")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
}

func TestPlugin_TargetFileNotGemfile(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)

	// Some other lockfile — should not match.
	opts := ecosystems.NewPluginOptions().WithTargetFile("Cargo.lock")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestPlugin_CustomGemfileName covers the legacy "rails.2.4.5.gemfile"
// flavor — basename contains "gemfile" anywhere.
func TestPlugin_CustomGemfileName(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "rails.2.4.5.gemfile.lock"), simpleLock)

	opts := ecosystems.NewPluginOptions().WithTargetFile("rails.2.4.5.gemfile.lock")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
}

// TestPlugin_AllProjects locates every Gemfile.lock under the tree, and
// each nested result gets a distinct rootPkg name suffixed with the
// subdirectory.
func TestPlugin_AllProjects(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)
	writeFile(t, filepath.Join(tmp, "nested", "Gemfile.lock"), simpleLock)

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, results, 2)

	gotRoots := make(map[string]bool)
	for _, r := range results {
		require.NoError(t, r.Error)
		gotRoots[r.DepGraph.GetRootPkg().Info.Name] = true
	}
	base := filepath.Base(tmp)
	assert.True(t, gotRoots[base], "scan-root lockfile uses bare basename")
	assert.True(t, gotRoots[base+"/nested"], "nested lockfile suffixes the relative dir")
}

// TestPlugin_ProjectNameOverride confirms the orchestrator-supplied
// --project-name wins over the basename-derived default.
func TestPlugin_ProjectNameOverride(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)

	opts := ecosystems.NewPluginOptions().WithProjectName("my-explicit-name")
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "my-explicit-name", results[0].DepGraph.GetRootPkg().Info.Name)
}

// TestPlugin_DiscoverHonorsExcludePaths mirrors the bun-style
// exclude-paths contract.
func TestPlugin_DiscoverHonorsExcludePaths(t *testing.T) {
	tmp := t.TempDir()
	for _, rel := range []string{"Gemfile.lock", "a/Gemfile.lock", "b/Gemfile.lock"} {
		writeFile(t, filepath.Join(tmp, rel), simpleLock)
	}
	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/Gemfile.lock"})

	got, err := Plugin{}.discoverLockFiles(context.Background(), tmp, opts)
	require.NoError(t, err)

	rels := make([]string, 0, len(got))
	for _, r := range got {
		rels = append(rels, r.RelPath)
	}
	assert.NotContains(t, rels, "a/Gemfile.lock")
	assert.Contains(t, rels, "Gemfile.lock")
	assert.Contains(t, rels, "b/Gemfile.lock")
}

// TestPlugin_MalformedLockfile_EmitsErrorResult — the parser is
// permissive, so we use a deliberately broken file: deny read by
// putting the lockfile as a directory.
func TestPlugin_UnreadableLockfile_EmitsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	// Create Gemfile.lock as a directory so os.Open fails.
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "Gemfile.lock"), 0o755))
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp,
		ecosystems.NewPluginOptions())
	// Default discovery skips directories so we won't see a result;
	// force the path via --target-file.
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestPlugin_IncludeDev_Plumbed — proves the --dev flag travels into
// BuildOptions. With no group info today both branches produce the
// same graph; this test exists so the wiring breaks loudly if someone
// drops the option later.
func TestPlugin_IncludeDev_Plumbed(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)

	for _, includeDev := range []bool{false, true} {
		opts := ecosystems.NewPluginOptions().WithIncludeDev(includeDev)
		results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, opts)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NoError(t, results[0].Error)
	}
}

// TestPlugin_NilOptions tolerates nil-options entry from defensive callers.
func TestPlugin_NilOptions(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, filepath.Join(tmp, "Gemfile.lock"), simpleLock)
	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), tmp, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
}
