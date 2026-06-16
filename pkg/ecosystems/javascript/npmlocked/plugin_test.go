package npmlocked

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// fakeExecutor returns a canned JSON payload as the npm ls output and
// records the RunOptions it was called with so tests can assert wiring.
type fakeExecutor struct {
	json    string
	err     error
	gotOpts RunOptions
}

func (f *fakeExecutor) Run(_ context.Context, _ string, opts RunOptions) (io.ReadCloser, error) {
	f.gotOpts = opts
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
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp,
		ecosystems.NewPluginOptions().WithAllProjects(true))
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

	// Per-workspace graph root uses the real semver from packages/logger/package.json,
	// not the synthetic file:packages/logger form.
	assert.Equal(t, "1.0.0", loggerResult.DepGraph.GetRootPkg().Info.Version,
		"workspace graph root uses real semver from its own package.json")
}

func TestPlugin_Workspace_WithoutAllProjects_EmitsSingleGraph(t *testing.T) {
	// Without --all-projects, a workspace project produces ONE graph (the root)
	// just like the legacy CLI single-project path. Workspace packages become
	// regular transitive deps in the root graph rather than separate projects.
	tmp := t.TempDir()
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
			}
		}
	}`

	plugin := newPlugin(&fakeExecutor{json: lsJSON})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "without --all-projects, one graph is emitted")

	r := results[0]
	require.NoError(t, r.Error)
	require.NotNil(t, r.DepGraph)
	assert.Equal(t, "my-workspace", r.DepGraph.GetRootPkg().Info.Name)

	// Workspace package walked transitively into the root graph (not held as a
	// stop-set leaf), so axios appears as a transitive dep.
	pkgIDs := make(map[string]bool)
	for _, p := range r.DepGraph.Pkgs {
		pkgIDs[p.ID] = true
	}
	assert.True(t, pkgIDs["@workspace/logger@1.0.0"], "workspace pkg with real version, not file: id")
	assert.True(t, pkgIDs["axios@1.14.0"], "workspace transitive walked into root graph")
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

func TestParseListOutput(t *testing.T) {
	t.Run("valid JSON decodes", func(t *testing.T) {
		raw := `{"name":"my-app","version":"1.0.0","dependencies":{"debug":{"version":"4.4.3"}}}`
		got, err := parseListOutput(bytes.NewReader([]byte(raw)))
		require.NoError(t, err)
		assert.Equal(t, "my-app", got.Name)
		assert.Equal(t, "1.0.0", got.Version)
		require.Contains(t, got.Dependencies, "debug")
		assert.Equal(t, "4.4.3", got.Dependencies["debug"].Version)
	})

	t.Run("malformed JSON errors", func(t *testing.T) {
		_, err := parseListOutput(bytes.NewReader([]byte(`{"name":`)))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding npm ls JSON")
	})

	t.Run("empty body errors", func(t *testing.T) {
		_, err := parseListOutput(bytes.NewReader(nil))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding npm ls JSON")
	})

	t.Run("problems field decodes", func(t *testing.T) {
		raw := `{
			"name": "app", "version": "1.0.0",
			"problems": [
				"missing: foo@^1.0.0, required by app@1.0.0",
				"invalid: bar@2.0.0"
			],
			"dependencies": {"debug": {"version": "4.4.3"}}
		}`
		got, err := parseListOutput(bytes.NewReader([]byte(raw)))
		require.NoError(t, err)
		assert.Equal(t, []string{
			"missing: foo@^1.0.0, required by app@1.0.0",
			"invalid: bar@2.0.0",
		}, got.Problems, "problems array preserved alongside partial tree")
		assert.Contains(t, got.Dependencies, "debug", "partial tree still parsed")
	})
}

// recordingLogger is a Logger that captures Info-level messages so tests can
// assert that problems were surfaced.
type recordingLogger struct {
	logger.Logger
	mu       sync.Mutex
	infoMsgs []string
}

func newRecordingLogger() *recordingLogger {
	return &recordingLogger{Logger: logger.Nop()}
}

func (r *recordingLogger) Info(_ context.Context, msg string, fields ...logger.Field) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := msg
	for _, f := range fields {
		entry += " " + f.Key + "=" + fmt.Sprint(f.Value)
	}
	r.infoMsgs = append(r.infoMsgs, entry)
}

func (r *recordingLogger) infoContains(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.infoMsgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func TestPlugin_OutOfSync_SurfacesProblemsAndStillBuildsGraph(t *testing.T) {
	// npm emits a `problems` array alongside a partial-but-usable dep tree
	// when the lockfile is out of sync. We should:
	//   - Still produce a dep graph from the partial tree (not error out).
	//   - Log each problem via Info so customers see actionable detail.
	tmp := t.TempDir()
	writeProject(t, tmp, "app")

	lsJSON := `{
		"name": "app", "version": "1.0.0",
		"problems": ["missing: missing-pkg@^1.0.0, required by app@1.0.0"],
		"dependencies": {"debug": {"version": "4.4.3"}}
	}`

	log := newRecordingLogger()
	plugin := newPlugin(&fakeExecutor{json: lsJSON})
	results, err := scatest.Run(context.Background(), plugin, log, tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error, "partial tree still produces a successful result")
	require.NotNil(t, results[0].DepGraph)

	// Problem surfaced via Info-level log.
	assert.True(t, log.infoContains("missing: missing-pkg@^1.0.0"),
		"problem from npm ls should be logged so customers see it")
}

func TestPlugin_IncludeDev_TranslatesToOmitDev(t *testing.T) {
	// IncludeDev is the single source of truth for dev-dep handling.
	// IncludeDev=false (the legacy CLI default) → OmitDev=true.
	// IncludeDev=true → OmitDev=false.
	tests := []struct {
		name        string
		opts        *ecosystems.SCAPluginOptions
		wantOmitDev bool
	}{
		{
			name:        "default options omit dev",
			opts:        ecosystems.NewPluginOptions(),
			wantOmitDev: true,
		},
		{
			name:        "IncludeDev=true keeps dev",
			opts:        ecosystems.NewPluginOptions().WithIncludeDev(true),
			wantOmitDev: false,
		},
		{
			name:        "IncludeDev=false explicit omits dev",
			opts:        ecosystems.NewPluginOptions().WithIncludeDev(false),
			wantOmitDev: true,
		},
		{
			name:        "nil options omit dev",
			opts:        nil,
			wantOmitDev: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			writeProject(t, tmp, "x")

			exec := &fakeExecutor{json: `{}`}
			plugin := newPlugin(exec)

			_, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, tt.opts)
			require.NoError(t, err)

			assert.Equal(t, tt.wantOmitDev, exec.gotOpts.OmitDev,
				"OmitDev should reflect IncludeDev (inverted)")
		})
	}
}

func TestPlugin_Shrinkwrap_Discovered(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"),
		[]byte(`{"name":"shrinkapp","version":"1.0.0"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "npm-shrinkwrap.json"), []byte("{}"), 0o600))

	plugin := newPlugin(&fakeExecutor{json: `{"name":"shrinkapp","version":"1.0.0"}`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "shrinkwrap-only project is scanned")
	assert.ElementsMatch(t,
		[]string{"npm-shrinkwrap.json", "package.json"},
		results[0].ProcessedFiles, "shrinkwrap is reported as the lockfile")
}

func TestPlugin_Shrinkwrap_PreferredOverPackageLock(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package.json"),
		[]byte(`{"name":"both","version":"1.0.0"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "npm-shrinkwrap.json"), []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "package-lock.json"), []byte("{}"), 0o600))

	plugin := newPlugin(&fakeExecutor{json: `{"name":"both","version":"1.0.0"}`})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1, "single scan when both lockfiles exist")
	// Shrinkwrap wins; package-lock.json is not in ProcessedFiles.
	assert.Contains(t, results[0].ProcessedFiles, "npm-shrinkwrap.json", "shrinkwrap is preferred")
	assert.NotContains(t, results[0].ProcessedFiles, "package-lock.json", "package-lock not used when shrinkwrap exists")
}

func TestPlugin_DiscoverLockFiles_AllProjects_ShrinkwrapPrecedence(t *testing.T) {
	// In --all-projects mode, when a directory contains both lockfile types,
	// shrinkwrap is kept and package-lock is suppressed (avoid running npm ls
	// twice in the same dir).
	tmp := t.TempDir()
	// dir-a: shrinkwrap only
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "a"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "a", "npm-shrinkwrap.json"), []byte("{}"), 0o600))
	// dir-b: package-lock only
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "b"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "b", "package-lock.json"), []byte("{}"), 0o600))
	// dir-c: both
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "c"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "c", "npm-shrinkwrap.json"), []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "c", "package-lock.json"), []byte("{}"), 0o600))

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	got, err := Plugin{}.discoverLockFiles(t.Context(), tmp, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.ElementsMatch(t,
		[]string{"a/npm-shrinkwrap.json", "b/package-lock.json", "c/npm-shrinkwrap.json"},
		rels, "shrinkwrap suppresses package-lock in same dir")
}

func TestPlugin_DiscoverLockFiles_TargetFileShrinkwrap(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "npm-shrinkwrap.json"), []byte("{}"), 0o600))

	opts := ecosystems.NewPluginOptions().WithTargetFile("npm-shrinkwrap.json")
	got, err := Plugin{}.discoverLockFiles(t.Context(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "npm-shrinkwrap.json", got[0].RelPath)
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
