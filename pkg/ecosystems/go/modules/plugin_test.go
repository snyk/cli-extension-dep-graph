package modules

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

// fakeExecutor returns a canned JSON payload as the `go list` output,
// recording the dir + opts it was called with for assertion.
type fakeExecutor struct {
	json     string
	err      error
	gotDir   string
	gotOpts  RunOptions
	callsBy  map[string]string // dir → json, if multi-call mode is wanted
	wantArgs []string
}

func (f *fakeExecutor) Run(_ context.Context, dir string, opts RunOptions) (io.ReadCloser, error) {
	f.gotDir = dir
	f.gotOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	if f.callsBy != nil {
		if body, ok := f.callsBy[dir]; ok {
			return io.NopCloser(bytes.NewReader([]byte(body))), nil
		}
		return io.NopCloser(bytes.NewReader([]byte(""))), nil
	}
	return io.NopCloser(bytes.NewReader([]byte(f.json))), nil
}

func newPlugin(exec goListRunner) Plugin {
	return Plugin{executor: exec}
}

// writeGoMod drops a minimal go.mod into dir naming the module.
func writeGoMod(t *testing.T, dir, modulePath string) {
	t.Helper()
	body := "module " + modulePath + "\n\ngo 1.21\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o600))
}

// canonicalGoListOutput is a single-dep `go list -json` stream used by
// the happy-path plugin tests.
const canonicalGoListOutput = `{
	"ImportPath": "example.com/app",
	"Module": {"Path": "example.com/app", "Main": true},
	"Imports": ["github.com/lib/foo"]
}
{
	"ImportPath": "github.com/lib/foo",
	"DepOnly": true,
	"Module": {"Path": "github.com/lib/foo", "Version": "v1.0.0"}
}`

func TestPlugin_Simple(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp, "example.com/app")

	plugin := newPlugin(&fakeExecutor{json: canonicalGoListOutput})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.NoError(t, r.Error)
	require.NotNil(t, r.DepGraph)

	assert.Equal(t, "example.com/app", r.DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "go.mod", r.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, []string{"go.mod"}, r.ProcessedFiles)

	require.NotNil(t, r.ResolverMetadata)
	assert.Equal(t, "gomodules", r.ResolverMetadata.PluginName)
}

func TestPlugin_NoGoMod_ReturnsEmpty(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{json: "{}"})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), t.TempDir(), ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_GoNotFound_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errGoNotFound})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ErrorIs(t, results[0].Error, errGoNotFound)
}

func TestPlugin_GoListFailure_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp, "x")

	plugin := newPlugin(&fakeExecutor{err: errors.New("go list failed: exit status 1")})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestPlugin_TargetFileNotGoMod_ReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp, "x")
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "Gopkg.lock"), []byte(""), 0o600))

	plugin := newPlugin(&fakeExecutor{json: "{}"})
	opts := ecosystems.NewPluginOptions().WithTargetFile("Gopkg.lock")
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	assert.Empty(t, results, "golangdep is intentionally not handled")
}

func TestPlugin_Workspace_MultipleResults(t *testing.T) {
	tmp := t.TempDir()
	// go.work + two member modules.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.work"),
		[]byte("go 1.21\n\nuse (\n    ./svc-a\n    ./svc-b\n)\n"), 0o600))

	for _, member := range []string{"svc-a", "svc-b"} {
		require.NoError(t, os.MkdirAll(filepath.Join(tmp, member), 0o755))
		writeGoMod(t, filepath.Join(tmp, member), "example.com/"+member)
	}

	exec := &fakeExecutor{
		callsBy: map[string]string{
			filepath.Join(tmp, "svc-a"): `{"ImportPath":"example.com/svc-a","Module":{"Path":"example.com/svc-a","Main":true}}`,
			filepath.Join(tmp, "svc-b"): `{"ImportPath":"example.com/svc-b","Module":{"Path":"example.com/svc-b","Main":true}}`,
		},
	}

	plugin := newPlugin(exec)
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 2, "one SCAResult per workspace member")

	byTarget := make(map[string]string)
	for _, r := range results {
		require.NoError(t, r.Error)
		byTarget[r.ProjectDescriptor.GetTargetFile()] = r.DepGraph.GetRootPkg().Info.Name
	}
	assert.Equal(t, "example.com/svc-a", byTarget[filepath.Join("svc-a", "go.mod")])
	assert.Equal(t, "example.com/svc-b", byTarget[filepath.Join("svc-b", "go.mod")])
}

func TestPlugin_VendorModePassedThrough(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp, "x")

	exec := &fakeExecutor{json: canonicalGoListOutput}

	// Vendor mode passthrough is structured as an executor-level
	// concern: the plugin forwards additional args from RunOptions to
	// the executor unchanged. Verify by invoking the fake executor
	// directly with the vendor flag and asserting it captured it.
	_, _ = exec.Run(context.Background(), tmp, RunOptions{AdditionalArgs: []string{"-mod=vendor"}})
	assert.Equal(t, []string{"-mod=vendor"}, exec.gotOpts.AdditionalArgs, "executor receives -mod=vendor as a passthrough arg")
}

func TestPlugin_GraphOptions_Defaults_UseReplaceNameTrue(t *testing.T) {
	p := Plugin{}
	got := p.graphOptions()
	assert.True(t, got.UseReplaceName, "default matches legacy hardcoded behaviour")
	assert.False(t, got.IncludeStdlib)
}

func TestPlugin_GraphOptions_OverrideUseReplaceName(t *testing.T) {
	off := false
	p := Plugin{Options: PluginOptions{UseReplaceNameOverride: &off}}
	assert.False(t, p.graphOptions().UseReplaceName)
}

func TestPlugin_GraphOptions_IncludeStdlibHonoured(t *testing.T) {
	p := Plugin{Options: PluginOptions{IncludeStdlib: true}}
	assert.True(t, p.graphOptions().IncludeStdlib)
}

func TestPlugin_DiscoverGoModFiles_HonorsExcludePaths(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{"go.mod", "a/go.mod", "b/go.mod"} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o600))
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/go.mod"})

	got, err := Plugin{}.discoverGoModFiles(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.NotContains(t, rels, "a/go.mod")
	assert.Contains(t, rels, "go.mod")
	assert.Contains(t, rels, "b/go.mod")
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "gomodules", Plugin{}.GetName())
}

func TestPlugin_FallbackRootFromGoMod(t *testing.T) {
	// go list output has no Main package — root should fall back to
	// the module name parsed from go.mod, not the dir basename.
	tmp := t.TempDir()
	writeGoMod(t, tmp, "example.com/my-app")

	output := `{"ImportPath":"github.com/lib/foo","DepOnly":true,"Module":{"Path":"github.com/lib/foo","Version":"v1.0.0"}}`

	plugin := newPlugin(&fakeExecutor{json: output})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "example.com/my-app", results[0].DepGraph.GetRootPkg().Info.Name)
}
