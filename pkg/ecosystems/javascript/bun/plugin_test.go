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
	assert.Equal(t, "bun.lock", scaResult.Metadata.TargetFile)

	pkgIDs := make(map[string]bool)
	for _, p := range scaResult.DepGraph.Pkgs {
		pkgIDs[p.ID] = true
	}

	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])
	assert.True(t, pkgIDs["@types/bun@1.3.11"])
}

func TestPlugin_Workspace_MegaDepGraph(t *testing.T) {
	plugin := newPlugin(&fakeExecutor{outputFile: "testdata/workspace/why_output.txt"})
	opts := ecosystems.NewPluginOptions()

	result, err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), "testdata/workspace", opts)
	require.NoError(t, err)

	// Always one result — the mega dep graph.
	require.Len(t, result.Results, 1)
	scaResult := result.Results[0]
	require.NoError(t, scaResult.Error)
	require.NotNil(t, scaResult.DepGraph)

	assert.Equal(t, "my-workspace", scaResult.DepGraph.GetRootPkg().Info.Name)

	pkgIDs := make(map[string]bool)
	for _, p := range scaResult.DepGraph.Pkgs {
		pkgIDs[p.ID] = true
	}

	// Workspace package appears as a node.
	assert.True(t, pkgIDs["@workspace/logger@workspace:packages/logger"])
	// Transitive deps of workspace package.
	assert.True(t, pkgIDs["axios@1.14.0"])
	assert.True(t, pkgIDs["follow-redirects@1.15.9"])
	// Root-level deps.
	assert.True(t, pkgIDs["debug@4.4.3"])
	assert.True(t, pkgIDs["ms@2.1.3"])
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
