package composer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// fakeExecutor returns a canned text-tree payload as composer's stdout, or
// a sentinel error.
type fakeExecutor struct {
	output string
	err    error

	// gotOpts captures the last RunOptions used to invoke the executor so
	// tests can assert on the dev-flag plumbing without inspecting argv.
	gotOpts RunOptions
	called  bool
}

func (f *fakeExecutor) Run(_ context.Context, _ string, opts RunOptions) (io.ReadCloser, error) {
	f.called = true
	f.gotOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(bytes.NewReader([]byte(f.output))), nil
}

func newPlugin(exec composerShowRunner) Plugin {
	return Plugin{executor: exec}
}

// writeProject writes a minimal composer.json (name + version) and a
// minimal composer.lock into dir.
func writeProject(t *testing.T, dir, name string) {
	t.Helper()
	pj := `{"name":"` + name + `","version":"1.0.0"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.json"), []byte(pj), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "composer.lock"),
		[]byte(`{"packages":[],"packages-dev":[]}`), 0o600))
}

func TestPlugin_Simple(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "vendor/my-app")

	output := strings.Join([]string{
		"guzzlehttp/guzzle 7.8.0 Guzzle is a PHP HTTP client library",
		"└──psr/http-message ^2.0",
	}, "\n")

	plugin := newPlugin(&fakeExecutor{output: output})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	require.NoError(t, r.Error)
	require.NotNil(t, r.DepGraph)
	assert.Equal(t, "vendor/my-app", r.DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "1.0.0", r.DepGraph.GetRootPkg().Info.Version)
	assert.Equal(t, "composer.json", r.ProjectDescriptor.GetTargetFile())
	assert.ElementsMatch(t,
		[]string{"composer.lock", "composer.json"},
		r.ProcessedFiles)

	require.NotNil(t, r.ResolverMetadata)
	assert.Equal(t, "composer", r.ResolverMetadata.PluginName)

	ids := make(map[string]bool)
	for _, p := range r.DepGraph.Pkgs {
		ids[p.ID] = true
	}
	assert.True(t, ids["guzzlehttp/guzzle@7.8.0"])
	assert.True(t, ids["psr/http-message@^2.0"])
}

func TestPlugin_RootNameFallbackToDir(t *testing.T) {
	tmp := t.TempDir()
	// composer.json with NO `name` — application style.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "composer.json"),
		[]byte(`{"description":"A composer application"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "composer.lock"),
		[]byte(`{"packages":[]}`), 0o600))

	plugin := newPlugin(&fakeExecutor{output: ""})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	// The fallback is the directory's base name.
	assert.Equal(t, filepath.Base(tmp), results[0].DepGraph.GetRootPkg().Info.Name)
}

func TestPlugin_NoComposerJson_FallsBackToDirName(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "composer.lock"),
		[]byte(`{"packages":[]}`), 0o600))

	plugin := newPlugin(&fakeExecutor{output: ""})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Equal(t, filepath.Base(tmp), results[0].DepGraph.GetRootPkg().Info.Name)
}

func TestPlugin_DevDepInclusion(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "vendor/my-app")

	// Default (no IncludeDev) ⇒ executor invoked with IncludeDev=false.
	fx := &fakeExecutor{output: ""}
	plugin := newPlugin(fx)
	_, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp,
		ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.False(t, fx.gotOpts.IncludeDev, "default options should not include dev")

	// Caller passes IncludeDev=true ⇒ executor invoked with IncludeDev=true.
	fx2 := &fakeExecutor{output: ""}
	plugin2 := newPlugin(fx2)
	_, err = scatest.Run(context.Background(), plugin2, logger.Nop(), tmp,
		ecosystems.NewPluginOptions().WithIncludeDev(true))
	require.NoError(t, err)
	assert.True(t, fx2.gotOpts.IncludeDev, "IncludeDev=true should propagate")
}

func TestPlugin_DevDepForcedViaPluginField(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "vendor/my-app")

	// Plugin.IncludeDev=true acts as a direct-caller override; even with the
	// default options (IncludeDev=false), dev should be on.
	fx := &fakeExecutor{output: ""}
	plugin := Plugin{executor: fx, IncludeDev: true}
	_, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp,
		ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.True(t, fx.gotOpts.IncludeDev)
}

func TestPlugin_NoLockfile_ReturnsEmpty(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{output: ""})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(),
		t.TempDir(), ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_ComposerNotFound_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "vendor/x")

	plugin := newPlugin(&fakeExecutor{err: errComposerNotFound})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(),
		tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ErrorIs(t, results[0].Error, errComposerNotFound)
}

func TestPlugin_ComposerVersionTooLow_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "vendor/x")

	plugin := newPlugin(&fakeExecutor{err: errComposerVersionTooLow})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(),
		tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.ErrorIs(t, results[0].Error, errComposerVersionTooLow)
}

func TestPlugin_ComposerRunFailure_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "vendor/x")

	plugin := newPlugin(&fakeExecutor{err: errors.New("composer show failed: exit status 2")})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(),
		tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
}

func TestPlugin_TargetFileNotComposerLock_ReturnsEmpty(t *testing.T) {
	tmp := t.TempDir()
	writeProject(t, tmp, "vendor/x")

	plugin := newPlugin(&fakeExecutor{output: ""})
	opts := ecosystems.NewPluginOptions().WithTargetFile("composer.json")
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(), tmp, opts)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_InvalidComposerJson_ReturnsErrorResult(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "composer.json"),
		[]byte(`{not json`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "composer.lock"),
		[]byte(`{}`), 0o600))

	plugin := newPlugin(&fakeExecutor{output: ""})
	results, err := scatest.Run(context.Background(), plugin, logger.Nop(),
		tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Error(t, results[0].Error)
	assert.Contains(t, results[0].Error.Error(), "composer.json")
}

func TestPlugin_DiscoverLockFiles_HonorsExcludePaths(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{"composer.lock", "a/composer.lock", "b/composer.lock"} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o600))
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/composer.lock"})

	got, err := Plugin{}.discoverLockFiles(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.NotContains(t, rels, "a/composer.lock")
	assert.Contains(t, rels, "composer.lock")
	assert.Contains(t, rels, "b/composer.lock")
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "composer", Plugin{}.GetName())
}
