package bun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

func (f *fakeExecutor) Run(_ context.Context, _ string) (io.Reader, error) {
	if f.err != nil {
		return nil, f.err
	}

	data, err := os.ReadFile(f.outputFile)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
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
	require.Len(t, result.ProcessedFiles, 1)
	assert.Equal(t, "bun.lock", result.ProcessedFiles[0])

	scaResult := result.Results[0]
	require.NoError(t, scaResult.Error)
	require.NotNil(t, scaResult.DepGraph)
	assert.Equal(t, "my-app", scaResult.DepGraph.GetRootPkg().Info.Name)
	assert.Equal(t, "package.json", scaResult.ProjectDescriptor.GetTargetFile())

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
	}

	rootResult := testFindResultByRoot(t, result.Results, "my-workspace")
	loggerResult := testFindResultByRoot(t, result.Results, "@workspace/logger")
	utilsResult := testFindResultByRoot(t, result.Results, "@workspace/utils")

	// Each dep graph's TargetFile should be the package.json for that workspace package.
	assert.Equal(t, "package.json", rootResult.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "packages/logger/package.json", loggerResult.ProjectDescriptor.GetTargetFile())
	assert.Equal(t, "packages/utils/package.json", utilsResult.ProjectDescriptor.GetTargetFile())

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

func (s *streamExecutor) Run(_ context.Context, _ string) (io.Reader, error) { return s.r, nil }

// TestParseWhyOutput_ReaderInterface confirms parseWhyOutput works with strings.NewReader.
func TestParseWhyOutput_ReaderInterface(t *testing.T) {
	input := strings.NewReader("debug@4.4.3\n  └─ my-app (requires ^4.4.3)\n\nms@2.1.3\n  └─ debug@4.4.3 (requires ^2.1.3)\n")

	out, err := parseWhyOutput(context.Background(), logger.Nop(), input)
	require.NoError(t, err)
	assert.Contains(t, out.ProdDeps, "debug@4.4.3")
	assert.Contains(t, out.Graph, "ms@2.1.3")
}
