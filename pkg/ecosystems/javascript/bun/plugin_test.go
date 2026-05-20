package bun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// testFindResultByRoot finds the SCAResult whose root package name equals rootName.
func testFindResultByRoot(t *testing.T, results []ecosystems.SCAResult, rootName string) ecosystems.SCAResult {
	t.Helper()

	for _, r := range results {
		if r.DepGraph != nil && r.DepGraph.GetRootPkg().Info.Name == rootName {
			return r
		}
	}

	t.Fatalf("no dep graph with root package %q", rootName)

	return ecosystems.SCAResult{}
}

// fakeExecutor implements bunWhyRunner using a fixture file for bun why output.
type fakeExecutor struct {
	outputFile string
	err        error
}

func (f *fakeExecutor) Run(_ context.Context, _ string) (io.ReadCloser, error) {
	if f.err != nil {
		return nil, f.err
	}

	data, err := os.ReadFile(f.outputFile)
	if err != nil {
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

func newPlugin(exec bunWhyRunner) Plugin {
	return Plugin{executor: exec}
}

func TestPlugin_Simple(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{outputFile: "testdata/simple/why_output.txt"})
	opts := ecosystems.NewPluginOptions()

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/simple", opts)
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.ElementsMatch(t, []string{"bun.lock", "package.json"}, result.ProcessedFiles)

	scaResult := result.Results[0]
	require.NoError(t, scaResult.Error)
	require.NotNil(t, scaResult.DepGraph)
	assert.Equal(t, "my-app", scaResult.DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "package.json", scaResult.ProjectDescriptor.GetTargetFile())

	// Validate ResolverMetadata
	assert.NotNil(t, scaResult.ResolverMetadata)
	assert.Equal(t, "bun", scaResult.ResolverMetadata.PluginName)

	pkgIDs := make(map[string]bool)
	for _, p := range scaResult.DepGraph.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])
	assert.True(t, pkgIDs["@types/bun@1.3.11"])

	dg := scaResult.DepGraph
	assert.Contains(t, nodeDeps(dg, "root-node"), "debug@4.4.3", "root → debug")
	assert.Contains(t, nodeDeps(dg, "root-node"), "@types/bun@1.3.11", "root → @types/bun")
	assert.Contains(t, nodeDeps(dg, "debug@4.4.3"), "ms@2.1.3", "debug → ms")
	assert.Empty(t, nodeDeps(dg, "ms@2.1.3"), "ms has no deps")
}

func TestPlugin_Workspace_MultipleDepGraphs(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{outputFile: "testdata/workspace/why_output.txt"})
	opts := ecosystems.NewPluginOptions()

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/workspace", opts)
	require.NoError(t, err)

	// Root graph + one per workspace package (logger + utils).
	require.Len(t, result.Results, 3)
	for _, r := range result.Results {
		require.NoError(t, r.Error)
		require.NotNil(t, r.DepGraph)

		// Validate ResolverMetadata
		assert.NotNil(t, r.ResolverMetadata)
		assert.Equal(t, "bun", r.ResolverMetadata.PluginName)
	}

	rootResult := testFindResultByRoot(t, result.Results, "my-workspace")
	loggerResult := testFindResultByRoot(t, result.Results, "@workspace/logger")
	utilsResult := testFindResultByRoot(t, result.Results, "@workspace/utils")

	// Each dep graph's TargetFile should be the package.json for that workspace package.
	assert.Equal(t, "package.json", rootResult.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "packages/logger/package.json", loggerResult.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "packages/utils/package.json", utilsResult.ProjectDescriptor.GetTargetFile())

	// All package.jsons (root + workspace members) plus bun.lock must be marked processed
	// so that other plugins (npm/yarn) don't re-scan them.
	assert.ElementsMatch(t, []string{
		"bun.lock",
		"package.json",
		"packages/logger/package.json",
		"packages/utils/package.json",
	}, result.ProcessedFiles)

	// Root graph: workspace packages are leaves; their transitive deps absent.
	rootGraph := rootResult.DepGraph
	loggerGraph := loggerResult.DepGraph
	assert.Contains(t, nodeDeps(rootGraph, "root-node"), "@workspace/logger@workspace:packages/logger", "root → logger")
	assert.Contains(t, nodeDeps(rootGraph, "root-node"), "@workspace/utils@workspace:packages/utils", "root → utils")
	assert.Contains(t, nodeDeps(rootGraph, "root-node"), "debug@4.4.3", "root → debug")
	assert.Empty(t, nodeDeps(rootGraph, "@workspace/logger@workspace:packages/logger"),
		"logger is a leaf in the root graph")
	assert.Contains(t, nodeDeps(rootGraph, "debug@4.4.3"), "ms@2.1.3", "debug → ms in root graph")

	// Logger workspace graph: logger's own subtree is fully walked.
	assert.Contains(t, nodeDeps(loggerGraph, "root-node"), "axios@1.14.0", "logger root → axios")
	assert.Contains(t, nodeDeps(loggerGraph, "axios@1.14.0"), "follow-redirects@1.15.9", "axios → follow-redirects")
}

func TestPlugin_NoBunLock_ReturnsEmpty(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{outputFile: "testdata/simple/why_output.txt"})
	opts := ecosystems.NewPluginOptions()

	// Point at a directory with no bun.lock.
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), t.TempDir(), opts)
	require.NoError(t, err)
	assert.Empty(t, result.Results)
	assert.Empty(t, result.ProcessedFiles)
}

func TestPlugin_BunNotFound_ReturnsErrorResult(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{err: errBunNotFound})
	opts := ecosystems.NewPluginOptions()

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/simple", opts)
	require.NoError(t, err) // plugin-level error is per-result, not fatal
	require.Len(t, result.Results, 1)
	assert.Error(t, result.Results[0].Error)
	assert.ErrorIs(t, result.Results[0].Error, errBunNotFound)
}

func TestPlugin_BunVersionTooLow_ReturnsErrorResult(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{err: errBunVersionTooLow})
	opts := ecosystems.NewPluginOptions()

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/simple", opts)
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.ErrorIs(t, result.Results[0].Error, errBunVersionTooLow)
}

func TestPlugin_BunWhyError_ReturnsErrorResult(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{err: errors.New("bun why failed: exit status 1")})
	opts := ecosystems.NewPluginOptions()

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/simple", opts)
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Error(t, result.Results[0].Error)
}

func TestPlugin_TargetFileNotBunLock_ReturnsEmpty(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{outputFile: "testdata/simple/why_output.txt"})
	opts := ecosystems.NewPluginOptions().WithTargetFile("package.json")

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/simple", opts)
	require.NoError(t, err)
	assert.Empty(t, result.Results)
}

// TestPlugin_StreamingError verifies that an error surfaced mid-stream from the
// executor (e.g. non-zero bun exit after some output) is captured as a result error.
func TestPlugin_StreamingError(t *testing.T) {
	// Executor that returns a reader which errors partway through.
	pr, pw := io.Pipe()
	go func() {
		if _, err := pw.Write([]byte("debug@4.4.3\n  └─ my-app (requires ^4)\n")); err != nil {
			pw.CloseWithError(fmt.Errorf("setup write failed: %w", err))
			return
		}
		pw.CloseWithError(errors.New("bun why failed: exit status 1\nstderr: something went wrong"))
	}()

	plugin := newPlugin(&streamExecutor{r: pr})
	opts := ecosystems.NewPluginOptions()

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/simple", opts)
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Error(t, result.Results[0].Error)
}

// streamExecutor injects an already-prepared io.Reader.
type streamExecutor struct{ r io.Reader }

func (s *streamExecutor) Run(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(s.r), nil
}

// dirAwareExecutor implements bunWhyRunner, returning per-directory bun why output.
// The outputs map keys are absolute directory paths.
type dirAwareExecutor struct {
	outputs map[string]string
}

func (d *dirAwareExecutor) Run(_ context.Context, dir string) (io.ReadCloser, error) {
	out, ok := d.outputs[dir]
	if !ok {
		return nil, fmt.Errorf("dirAwareExecutor: no output configured for dir %q", dir)
	}
	return io.NopCloser(strings.NewReader(out)), nil
}

// TestPlugin_AllProjects_WorkspacesWithSubpackages proves that when scanning a
// directory with two independent bun workspaces (backend/ and frontend/), each
// containing sub-packages, every SCAResult.ProjectDescriptor.TargetFile points
// to a package.json — never to a bun.lock.
func TestPlugin_AllProjects_WorkspacesWithSubpackages(t *testing.T) {
	tmp := t.TempDir()

	// Create bun.lock + root package.json for each workspace root.
	for _, ws := range []struct {
		dir, name string
	}{
		{"backend", "bun-backend"},
		{"frontend", "bun-frontend"},
	} {
		require.NoError(t, os.MkdirAll(filepath.Join(tmp, ws.dir), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(tmp, ws.dir, "bun.lock"), nil, 0o600))
		require.NoError(t, os.WriteFile(
			filepath.Join(tmp, ws.dir, "package.json"),
			[]byte(`{"name":"`+ws.name+`","version":"1.0.0"}`),
			0o600,
		))
	}

	// bun why output for backend: three workspace sub-packages (1, 2, 3).
	backendWhy := strings.Join([]string{
		"ws-1@workspace:1",
		"  └─ bun-backend (requires workspace:^1.0.0)",
		"",
		"ws-2@workspace:2",
		"  └─ bun-backend (requires workspace:^1.0.0)",
		"",
		"ws-3@workspace:3",
		"  └─ bun-backend (requires workspace:^1.0.0)",
		"",
		"bun-backend@",
		"",
	}, "\n")

	// bun why output for frontend: three workspace sub-packages (3, 4, 5).
	// Sub-package "3" shares its numeric dir name with backend/3, proving that
	// TargetFiles are correctly scoped under their own workspace root.
	frontendWhy := strings.Join([]string{
		"ws-3@workspace:3",
		"  └─ bun-frontend (requires workspace:^1.0.0)",
		"",
		"ws-4@workspace:4",
		"  └─ bun-frontend (requires workspace:^1.0.0)",
		"",
		"ws-5@workspace:5",
		"  └─ bun-frontend (requires workspace:^1.0.0)",
		"",
		"bun-frontend@",
		"",
	}, "\n")

	exec := &dirAwareExecutor{outputs: map[string]string{
		filepath.Join(tmp, "backend"):  backendWhy,
		filepath.Join(tmp, "frontend"): frontendWhy,
	}}

	plugin := newPlugin(exec)
	opts := ecosystems.NewPluginOptions().WithAllProjects(true)

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), tmp, opts)
	require.NoError(t, err)
	require.Len(t, result.Results, 8, "4 dep graphs per workspace (root + 3 sub-packages) × 2 workspaces")

	for i, r := range result.Results {
		require.NoError(t, r.Error, "result[%d] must not carry an error", i)
		require.NotNil(t, r.DepGraph, "result[%d] must have a dep graph", i)

		// Validate ResolverMetadata
		assert.NotNil(t, r.ResolverMetadata, "result[%d] ResolverMetadata should not be nil", i)
		assert.Equal(t, "bun", r.ResolverMetadata.PluginName, "result[%d] PluginName should be 'bun'", i)
	}

	wantTargetFiles := []string{
		"backend/package.json",
		"backend/1/package.json",
		"backend/2/package.json",
		"backend/3/package.json",
		"frontend/package.json",
		"frontend/3/package.json",
		"frontend/4/package.json",
		"frontend/5/package.json",
	}

	gotTargetFiles := make([]string, len(result.Results))
	for i, r := range result.Results {
		gotTargetFiles[i] = r.ProjectDescriptor.GetTargetFile()
	}

	assert.ElementsMatch(t, wantTargetFiles, gotTargetFiles,
		"each dep graph must point to its package.json, not to bun.lock")

	for _, tf := range gotTargetFiles {
		assert.NotContains(t, tf, "bun.lock",
			"TargetFile must never be a lockfile path")
	}
}

// TestPlugin_NoName_ReturnsError verifies that a root package.json without a "name" field
// produces an error result rather than a broken dep graph. bun cannot reference an unnamed
// root in why output, so direct root deps would be invisible and the graph would be wrong.
func TestPlugin_NoName_ReturnsError(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "bun.lock"), nil, 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(tmp, "package.json"),
		[]byte(`{"version":"1.0.0"}`), // no name field
		0o600,
	))

	plugin := newPlugin(&fakeExecutor{}) // executor is never reached
	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), tmp, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, result.Results, 1)
	assert.Error(t, result.Results[0].Error)
	assert.Contains(t, result.Results[0].Error.Error(), `"name"`)
}

// TestParseWhyOutput_ReaderInterface confirms parseWhyOutput works with strings.NewReader.
func TestParseWhyOutput_ReaderInterface(t *testing.T) {
	input := strings.NewReader("debug@4.4.3\n  └─ my-app (requires ^4.4.3)\n\nms@2.1.3\n  └─ debug@4.4.3 (requires ^2.1.3)\n")

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)
	assert.Contains(t, out.ProdDeps, "debug@4.4.3")
	assert.Contains(t, out.Graph, "ms@2.1.3")
}

// TestPlugin_DiscoverLockFiles_HonorsExcludePaths locks in that the bun plugin reads
// `opts.Global.ExcludePaths` and passes those paths through to the discovery layer's
// exclude filter — same contract as the other discovery plugins.
func TestPlugin_DiscoverLockFiles_HonorsExcludePaths(t *testing.T) {
	tmpDir := t.TempDir()
	for _, rel := range []string{"bun.lock", "a/bun.lock", "b/bun.lock"} {
		full := filepath.Join(tmpDir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(""), 0o600))
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(true).
		WithExcludePaths([]string{"a/bun.lock"})

	got, err := Plugin{}.discoverLockFiles(t.Context(), tmpDir, opts)
	require.NoError(t, err)

	rels := make([]string, len(got))
	for i, r := range got {
		rels[i] = r.RelPath
	}
	assert.NotContains(t, rels, "a/bun.lock",
		"discovery must skip the path supplied via opts.Global.ExcludePaths")
	assert.Contains(t, rels, "bun.lock")
	assert.Contains(t, rels, "b/bun.lock")
}
