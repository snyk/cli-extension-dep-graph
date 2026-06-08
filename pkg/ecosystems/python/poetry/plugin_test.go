//go:build !integration
// +build !integration

package poetry

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

// fakeRunner satisfies poetryRunner from a file or in-memory bytes,
// and records the includeDev argument it was called with.
type fakeRunner struct {
	outputFile  string
	output      []byte
	err         error
	gotDir      string
	gotInclDev  bool
	callCount   int
}

func (f *fakeRunner) Run(_ context.Context, dir string, includeDev bool) (io.ReadCloser, error) {
	f.callCount++
	f.gotDir = dir
	f.gotInclDev = includeDev
	if f.err != nil {
		return nil, f.err
	}
	if f.outputFile != "" {
		data, err := os.ReadFile(f.outputFile)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return io.NopCloser(bytes.NewReader(f.output)), nil
}

func newPluginWith(runner poetryRunner) Plugin {
	return Plugin{executor: runner}
}

// scratchProject writes a minimal poetry project (manifest + lockfile)
// into a temp directory and returns the directory path. The lockfile is
// empty because the fakeRunner short-circuits poetry entirely — its
// presence just lets discovery pick the directory up.
func scratchProject(t *testing.T, manifest string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, PyprojectTomlFileName), []byte(manifest), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, LockFileName), []byte("# stub"), 0o600))
	return dir
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "poetry", Plugin{}.GetName())
}

func TestPlugin_BuildDepGraphsFromDir_SimpleHappyPath(t *testing.T) {
	dir := scratchProject(t, `[tool.poetry]
name = "myapp"
version = "1.0.0"
`)
	runner := &fakeRunner{outputFile: filepath.Join("testdata", "tree_v2_groups.txt")}
	plugin := newPluginWith(runner)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)

	assert.Equal(t, "myapp", results[0].DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "poetry", results[0].ResolverMetadata.PluginName)
	assert.Equal(t, PyprojectTomlFileName, results[0].ProjectDescriptor.GetTargetFile())
	assert.ElementsMatch(t,
		[]string{LockFileName, PyprojectTomlFileName},
		results[0].ProcessedFiles,
	)
}

func TestPlugin_HonorsProjectNameOverride(t *testing.T) {
	dir := scratchProject(t, `[tool.poetry]
name = "from-manifest"
version = "9.9.9"
`)
	runner := &fakeRunner{outputFile: filepath.Join("testdata", "tree_simple.txt")}
	plugin := newPluginWith(runner)

	opts := ecosystems.NewPluginOptions().WithProjectName("explicit-override")
	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Equal(t, "explicit-override", results[0].DepGraph.GetRootPkg().Info.Name,
		"--project-name must take precedence over the manifest name")
}

func TestPlugin_IncludeDev_ControlsExecutorFlag(t *testing.T) {
	dir := scratchProject(t, `[project]
name = "v2app"
version = "0.1.0"
`)

	t.Run("default_excludes_dev", func(t *testing.T) {
		runner := &fakeRunner{outputFile: filepath.Join("testdata", "tree_simple.txt")}
		plugin := newPluginWith(runner)
		_, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir,
			ecosystems.NewPluginOptions())
		require.NoError(t, err)
		assert.False(t, runner.gotInclDev,
			"IncludeDev defaults to false, executor must be told includeDev=false")
	})

	t.Run("include_dev_propagates_to_executor", func(t *testing.T) {
		runner := &fakeRunner{outputFile: filepath.Join("testdata", "tree_simple.txt")}
		plugin := newPluginWith(runner)
		_, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir,
			ecosystems.NewPluginOptions().WithIncludeDev(true))
		require.NoError(t, err)
		assert.True(t, runner.gotInclDev,
			"IncludeDev=true must reach the executor so it omits --without dev")
	})
}

func TestPlugin_NoLockfile_NoResults(t *testing.T) {
	dir := t.TempDir() // empty
	plugin := newPluginWith(&fakeRunner{})
	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestPlugin_RunnerError_BecomesErrorResult(t *testing.T) {
	dir := scratchProject(t, `[tool.poetry]
name = "myapp"
version = "1.0.0"
`)
	runner := &fakeRunner{err: errPoetryNotFound}
	plugin := newPluginWith(runner)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err, "runner failure must not abort the run; it surfaces as an SCAResult.Error")
	require.Len(t, results, 1)
	require.Error(t, results[0].Error)
	assert.True(t, errors.Is(results[0].Error, errPoetryNotFound))
}

func TestPlugin_ExtrasAndCircularAreSafe(t *testing.T) {
	// One project per fixture; mostly checks we don't crash + the
	// expected nodes appear.
	cases := map[string]string{
		"extras":   "tree_with_extras.txt",
		"circular": "tree_circular.txt",
	}
	for name, fx := range cases {
		t.Run(name, func(t *testing.T) {
			dir := scratchProject(t, `[tool.poetry]
name = "fixture"
version = "0.0.0"
`)
			runner := &fakeRunner{outputFile: filepath.Join("testdata", fx)}
			plugin := newPluginWith(runner)
			results, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir,
				ecosystems.NewPluginOptions())
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NoError(t, results[0].Error)
			require.NotNil(t, results[0].DepGraph)
		})
	}
}

func TestPlugin_AllProjects_FindsNested(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, PyprojectTomlFileName), []byte(`[tool.poetry]
name = "root-pkg"
version = "0.1.0"
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, LockFileName), []byte("# stub"), 0o600))

	nested := filepath.Join(root, "services", "api")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(nested, PyprojectTomlFileName), []byte(`[tool.poetry]
name = "api"
version = "0.1.0"
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(nested, LockFileName), []byte("# stub"), 0o600))

	runner := &fakeRunner{outputFile: filepath.Join("testdata", "tree_simple.txt")}
	plugin := newPluginWith(runner)

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), root, opts)
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, 2, runner.callCount, "executor should run once per discovered lockfile")
}

func TestPlugin_TargetFile_NonPoetryLock_Ignored(t *testing.T) {
	dir := scratchProject(t, `[tool.poetry]
name = "myapp"
version = "1.0.0"
`)
	runner := &fakeRunner{outputFile: filepath.Join("testdata", "tree_simple.txt")}
	plugin := newPluginWith(runner)

	tf := "package.json"
	opts := ecosystems.NewPluginOptions()
	opts.Global.TargetFile = &tf

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir, opts)
	require.NoError(t, err)
	assert.Empty(t, results, "non-poetry target file must be a no-op so other plugins can claim it")
	assert.Equal(t, 0, runner.callCount)
}

func TestManifestRelPath(t *testing.T) {
	assert.Equal(t, "pyproject.toml", manifestRelPath("poetry.lock"))
	assert.Equal(t, "svc/pyproject.toml", manifestRelPath("svc/poetry.lock"))
	assert.Equal(t, "a/b/pyproject.toml", manifestRelPath("a/b/poetry.lock"))
}

func TestProcessedFilesFor(t *testing.T) {
	assert.Equal(t, []string{"poetry.lock", "pyproject.toml"}, processedFilesFor("."))
	assert.Equal(t, []string{"poetry.lock", "pyproject.toml"}, processedFilesFor(""))
	assert.Equal(t, []string{"svc/poetry.lock", "svc/pyproject.toml"}, processedFilesFor("svc"))
}
