package cargo

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// fakeExecutor returns canned cargo tree output (or a sentinel error) so
// plugin-level tests can exercise the discovery → exec → parse → build
// pipeline without a real cargo binary.
type fakeExecutor struct {
	output string
	err    error
}

func (f *fakeExecutor) Run(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}
	return io.NopCloser(strings.NewReader(f.output)), nil
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "cargo", Plugin{}.GetName())
}

func TestBuildDepGraphsFromDir_HappyPath_SingleCrate(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))

	output := `0my-app v0.1.0
1serde v1.0.193
2serde_derive v1.0.193 (proc-macro)
1tokio v1.35.0
`

	plugin := Plugin{executor: &fakeExecutor{output: output}}
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	require.NoError(t, result.Results[0].Error)

	dg := result.Results[0].DepGraph
	require.NotNil(t, dg)
	assert.Equal(t, "my-app", dg.GetRootPkg().Info.Name)
	assert.Equal(t, "0.1.0", dg.GetRootPkg().Info.Version)
	assert.Equal(t, "cargo", dg.PkgManager.Name)
	assert.Len(t, dg.Pkgs, 4)

	tf := result.Results[0].ProjectDescriptor.GetTargetFile()
	assert.Equal(t, cargoTomlFile, tf)
	assert.Equal(t, "cargo", result.Results[0].ProjectDescriptor.Identity.ProjectType)
}

func TestBuildDepGraphsFromDir_NoLockfile(t *testing.T) {
	plugin := Plugin{}
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, t.TempDir(), &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	assert.Empty(t, result.Results)
	assert.Empty(t, result.ProcessedFiles)
}

func TestBuildDepGraphsFromDir_CargoNotFound(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))

	plugin := Plugin{executor: &fakeExecutor{err: errCargoNotFound}}
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	require.Error(t, result.Results[0].Error)
	assert.Contains(t, result.Results[0].Error.Error(), "cargo is not installed")
	assert.True(t, errors.Is(result.Results[0].Error, errCargoNotFound))
}

func TestBuildDepGraphsFromDir_TargetFileNotCargoLock(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(""), 0o600))

	tf := "some-other-file.txt"
	plugin := Plugin{}
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), nil, dir,
		(&ecosystems.SCAPluginOptions{}).WithTargetFile(tf))
	require.NoError(t, err)
	assert.Empty(t, result.Results, "non-Cargo.lock target file should produce no results")
}
