package swiftpm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// fakeExecutor returns canned JSON output for `swift package show-dependencies`.
type fakeExecutor struct {
	json string
	err  error

	// gotDir / gotArgs capture what the plugin passed to Run for argument-
	// propagation assertions.
	gotDir  string
	gotArgs []string
}

func (f *fakeExecutor) Run(_ context.Context, dir string, extraArgs []string) (io.ReadCloser, error) {
	f.gotDir = dir
	f.gotArgs = append([]string(nil), extraArgs...)
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(bytes.NewReader([]byte(f.json))), nil
}

func newPlugin(exec swiftRunner) Plugin {
	return Plugin{executor: exec}
}

// writeSwiftProject writes a minimal Package.swift declaring the given name.
func writeSwiftProject(t *testing.T, dir, name string) {
	t.Helper()
	manifest := `// swift-tools-version:5.6
import PackageDescription
let package = Package(name: "` + name + `", dependencies: [])
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, packageManifestFile), []byte(manifest), 0o600))
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "swiftpm", Plugin{}.GetName())
}

func TestPlugin_Simple(t *testing.T) {
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "my-app")

	showDepsJSON := `{
		"identity": "my-app",
		"name": "my-app",
		"url": "/tmp/my-app",
		"version": "unspecified",
		"dependencies": [
			{
				"identity": "grpc-swift",
				"name": "grpc-swift",
				"url": "https://github.com/grpc/grpc-swift.git",
				"version": "1.16.0",
				"dependencies": [
					{
						"identity": "swift-nio",
						"name": "swift-nio",
						"url": "https://github.com/apple/swift-nio.git",
						"version": "2.54.0",
						"dependencies": []
					}
				]
			}
		]
	}`

	exec := &fakeExecutor{json: showDepsJSON}
	plugin := newPlugin(exec)
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.NoError(t, r.Error)
	require.NotNil(t, r.DepGraph)

	assert.Equal(t, "my-app", r.DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "swift", r.DepGraph.PkgManager.Name)
	assert.Equal(t, packageManifestFile, r.ProjectDescriptor.GetTargetFile())
	assert.ElementsMatch(t, []string{packageManifestFile}, r.ProcessedFiles)

	require.NotNil(t, r.ResolverMetadata)
	assert.Equal(t, "swiftpm", r.ResolverMetadata.PluginName)
	assert.Equal(t, packageManifestFile, r.ResolverMetadata.NormalisedTargetFile)

	pkgIDs := make(map[string]bool)
	for _, p := range r.DepGraph.Pkgs {
		pkgIDs[p.ID] = true
	}
	assert.True(t, pkgIDs["github.com/grpc/grpc-swift@1.16.0"])
	assert.True(t, pkgIDs["github.com/apple/swift-nio@2.54.0"])

	// Plugin should hand the manifest's parent directory to the executor.
	assert.Equal(t, tmp, exec.gotDir)
	assert.Empty(t, exec.gotArgs, "plugin currently does not forward extra args")
}

func TestPlugin_Simple_WithPackageResolved_AddedToProcessedFiles(t *testing.T) {
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "my-app")
	require.NoError(t, os.WriteFile(filepath.Join(tmp, packageResolvedFile),
		[]byte(`{"pins":[],"version":2}`), 0o600))

	plugin := newPlugin(&fakeExecutor{json: `{"name":"my-app","url":"/tmp","version":"unspecified","dependencies":[]}`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ElementsMatch(t, []string{packageManifestFile, packageResolvedFile}, results[0].ProcessedFiles)
}

// TestPlugin_TargetFileSeparatorFixed exercises the audit fix.
//
// Legacy snyk-swiftpm-plugin (lib/index.ts) reconstructed targetFile as
// `${pathToPosix(targetFile)}Package.swift`, which produces e.g.
// "subdir/Package.swift" → "subdirPackage.swift" (missing separator).
// The new plugin uses the discovered manifest's relPath directly, which
// includes the separator. This test pins down that intentional divergence.
func TestPlugin_TargetFileSeparatorFixed(t *testing.T) {
	tmp := t.TempDir()
	subdir := filepath.Join(tmp, "subdir")
	require.NoError(t, os.MkdirAll(subdir, 0o755))
	writeSwiftProject(t, subdir, "nested-app")

	targetFile := filepath.Join(subdir, packageManifestFile)
	plugin := newPlugin(&fakeExecutor{json: `{"name":"nested-app","url":"/tmp","version":"unspecified","dependencies":[]}`})
	opts := ecosystems.NewPluginOptions().WithTargetFile(targetFile)

	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)

	tf := results[0].ProjectDescriptor.GetTargetFile()
	// The legacy bug would have produced "subdirPackage.swift".
	// The fixed behaviour produces "subdir/Package.swift" on POSIX
	// (or "subdir\Package.swift" on Windows — both still have a separator).
	assert.Equal(t, filepath.Join("subdir", packageManifestFile), tf,
		"separator between dir and basename must be preserved (audit fix vs legacy)")
	assert.NotEqual(t, "subdirPackage.swift", tf,
		"must not regress to the legacy bug shape")
}

func TestPlugin_NoManifest_ReturnsEmpty(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{json: `{}`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), t.TempDir(), ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_TargetFileNotPackageSwift_ReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{json: `{}`})
	opts := ecosystems.NewPluginOptions().WithTargetFile("package.json")
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_SwiftNotFound_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errSwiftNotFound})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ErrorIs(t, results[0].Error, errSwiftNotFound)
	require.NotNil(t, results[0].ResolverMetadata)
	assert.Equal(t, "swiftpm", results[0].ResolverMetadata.PluginName)
}

func TestPlugin_SwiftVersionTooLow_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errSwiftVersionTooLow})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ErrorIs(t, results[0].Error, errSwiftVersionTooLow)
}

func TestPlugin_SwiftRunFailure_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errors.New("swift package show-dependencies failed: exit status 1")})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestPlugin_MissingPackageSwiftWithJunk_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	// No Package.swift at all but Package.resolved present — discovery
	// returns nothing, so we get an empty result set.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, packageResolvedFile), []byte(`{}`), 0o600))

	plugin := newPlugin(&fakeExecutor{json: `{}`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_UnparseableSwiftOutput_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{json: `not json`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Error(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error(), "parsing swift show-dependencies output")
}

func TestPlugin_DiscoverManifests_HonorsExcludePaths(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{"Package.swift", "a/Package.swift", "b/Package.swift"} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o600))
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/Package.swift"})

	got, err := Plugin{}.discoverManifests(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.NotContains(t, rels, "a/Package.swift")
	assert.Contains(t, rels, "Package.swift")
	assert.Contains(t, rels, "b/Package.swift")
}

func TestPlugin_DiscoverManifests_ExcludesBuildAndSwiftpm(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{
		"Package.swift",
		".build/checkouts/sub/Package.swift",
		".swiftpm/config/Package.swift",
	} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o600))
	}

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	got, err := Plugin{}.discoverManifests(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.ElementsMatch(t, []string{"Package.swift"}, rels,
		".build and .swiftpm subtrees must not yield discovered manifests")
}

func TestPlugin_DefaultDiscovery_NoSubdirRecursion(t *testing.T) {
	// Without --all-projects, only the root Package.swift is considered.
	tmp := t.TempDir()
	writeSwiftProject(t, tmp, "root")
	subdir := filepath.Join(tmp, "sub")
	require.NoError(t, os.MkdirAll(subdir, 0o755))
	writeSwiftProject(t, subdir, "sub-pkg")

	plugin := newPlugin(&fakeExecutor{json: `{"name":"root","url":"/tmp","version":"unspecified","dependencies":[]}`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "default mode yields only the root manifest")
	assert.Equal(t, "root", results[0].DepGraph.GetRootPkg().Info.Name)
}
