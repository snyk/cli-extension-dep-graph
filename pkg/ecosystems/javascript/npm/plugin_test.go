package npm

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

// fakeExecutor returns a canned JSON payload as the npm ls output.
type fakeExecutor struct {
	json string
	err  error
}

func (f *fakeExecutor) Run(_ context.Context, _ string, _ RunOptions) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(bytes.NewReader([]byte(f.json))), nil
}

func newPlugin(exec npmLsRunner) Plugin {
	return Plugin{executor: exec}
}

// writeProject writes a minimal package.json (version 1.0.0) and an empty
// package-lock.json into dir.
func writeProject(t *testing.T, dir, name string) {
	t.Helper()
	pkg := `{"name":"` + name + `","version":"1.0.0"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o600))
}

func TestPlugin_Simple(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "my-app")

	lsJSON := `{
		"name": "my-app",
		"version": "1.0.0",
		"dependencies": {
			"debug": {
				"version": "4.4.3",
				"dependencies": {
					"ms": {"version": "2.1.3"}
				}
			}
		}
	}`

	plugin := newPlugin(&fakeExecutor{json: lsJSON})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.NoError(t, r.Error)
	require.NotNil(t, r.DepGraph)
	assert.Equal(t, "my-app", r.DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "package.json", r.ProjectDescriptor.GetTargetFile())
	assert.ElementsMatch(t, []string{"package-lock.json", "package.json"}, r.ProcessedFiles)

	require.NotNil(t, r.ResolverMetadata)
	assert.Equal(t, "npm", r.ResolverMetadata.PluginName)

	pkgIDs := make(map[string]bool)
	for _, p := range r.DepGraph.Pkgs {
		pkgIDs[p.ID] = true
	}
	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])
}

func TestPlugin_Workspace_MultipleDepGraphs(t *testing.T) {
	tmp := t.TempDir()
	// Root package.json with workspaces declaration and a real lockfile that
	// records the workspace package's canonical directory — readWorkspacePaths
	// reads from this to resolve the malformed file:../../ paths npm ls emits.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"),
		[]byte(`{"name":"my-workspace","version":"1.0.0","workspaces":["packages/*"]}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package-lock.json"), []byte(`{
		"packages": {
			"": {"name":"my-workspace","version":"1.0.0"},
			"packages/logger": {"name":"@workspace/logger","version":"1.0.0"},
			"node_modules/@workspace/logger": {"resolved":"packages/logger","link":true}
		}
	}`), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "packages", "logger"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(tmp, "packages", "logger", "package.json"),
		[]byte(`{"name":"@workspace/logger","version":"1.0.0"}`), 0o600))

	lsJSON := `{
		"name": "my-workspace",
		"version": "1.0.0",
		"dependencies": {
			"@workspace/logger": {
				"version": "1.0.0",
				"resolved": "file:packages/logger",
				"dependencies": {
					"axios": {"version": "1.14.0"}
				}
			},
			"debug": {"version": "4.4.3"}
		}
	}`

	plugin := newPlugin(&fakeExecutor{json: lsJSON})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 2)

	var rootResult, loggerResult ecosystems.SCAResult
	for _, r := range results {
		require.NoError(t, r.Error)
		require.NotNil(t, r.DepGraph)
		switch r.DepGraph.GetRootPkg().Info.Name {
		case "my-workspace":
			rootResult = r
		case "@workspace/logger":
			loggerResult = r
		}
	}

	require.NotNil(t, rootResult.DepGraph, "root graph emitted")
	require.NotNil(t, loggerResult.DepGraph, "workspace graph emitted")

	assert.Equal(t, "package.json", rootResult.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "packages/logger/package.json", loggerResult.ProjectDescriptor.GetTargetFile())

	assert.ElementsMatch(t,
		[]string{"package-lock.json", "package.json"},
		rootResult.ProcessedFiles)
	assert.ElementsMatch(t,
		[]string{"package-lock.json", "packages/logger/package.json"},
		loggerResult.ProcessedFiles)

	// Workspace logger is a leaf in root graph; its subtree lives in its own graph.
	loggerID := "@workspace/logger@file:packages/logger"
	assert.Empty(t, nodeDeps(rootResult.DepGraph, loggerID), "logger is a leaf in root")
	assert.Contains(t, nodeDeps(loggerResult.DepGraph, "root-node"), "axios@1.14.0", "axios in logger graph")
}

func TestPlugin_NoLockfile_ReturnsEmpty(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{json: `{}`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), t.TempDir(), ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_NpmNotFound_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errNpmNotFound})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ErrorIs(t, results[0].Error, errNpmNotFound)
}

func TestPlugin_NpmVersionTooLow_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errNpmVersionTooLow})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ErrorIs(t, results[0].Error, errNpmVersionTooLow)
}

func TestPlugin_NpmRunFailure_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errors.New("npm ls failed: exit status 1")})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestPlugin_TargetFileNotPackageLock_ReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{json: `{}`})
	opts := ecosystems.NewPluginOptions().WithTargetFile("package.json")
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_MissingPackageJSON_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package-lock.json"), []byte("{}"), 0o600))

	plugin := newPlugin(&fakeExecutor{json: `{}`}) // executor is never reached
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error(), "package.json")
}

func TestPlugin_DiscoverLockFiles_HonorsExcludePaths(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{"package-lock.json", "a/package-lock.json", "b/package-lock.json"} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o600))
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/package-lock.json"})

	got, err := Plugin{}.discoverLockFiles(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.NotContains(t, rels, "a/package-lock.json")
	assert.Contains(t, rels, "package-lock.json")
	assert.Contains(t, rels, "b/package-lock.json")
}
