package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

func TestNativePlugin_Resolution(t *testing.T) {
	for _, tt := range []struct {
		name         string
		allProjects  bool
		failFast     bool
		firstResults []ecosystems.SCAResult
		firstErr     error
		wantResults  int
		wantSecond   bool
	}{
		{name: "empty native continues", wantResults: 1, wantSecond: true},
		{name: "default native precedence", firstResults: []ecosystems.SCAResult{{ProcessedFiles: []string{"Cargo.lock"}}}, wantResults: 1},
		{name: "default result without files stops", firstResults: []ecosystems.SCAResult{{}}, wantResults: 1},
		{
			name: "all projects runs each native", allProjects: true,
			firstResults: []ecosystems.SCAResult{{ProcessedFiles: []string{"Cargo.lock", "Cargo.lock"}}}, wantResults: 2, wantSecond: true,
		},
		{name: "all projects continues after setup error", allProjects: true, firstErr: context.DeadlineExceeded, wantResults: 2, wantSecond: true},
		{name: "default setup error takes precedence", firstErr: context.DeadlineExceeded, wantResults: 1},
		{name: "fail fast setup error skips later native", allProjects: true, failFast: true, firstErr: context.DeadlineExceeded, wantResults: 1},
		{
			name: "fail fast result error skips later native", allProjects: true, failFast: true,
			firstResults: []ecosystems.SCAResult{{Error: context.DeadlineExceeded}}, wantResults: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first := &mockPlugin{name: "cargo", results: tt.firstResults, err: tt.firstErr}
			second := &mockPlugin{name: "dotnet", results: []ecosystems.SCAResult{{ProcessedFiles: []string{"project.assets.json"}}}}
			registry := &PluginRegistry{plugins: []ecosystems.SCAPlugin{first, second}}
			backing := []string{"original", "spare1", "spare2", "spare3"}
			opts := ecosystems.NewPluginOptions().WithAllProjects(tt.allProjects).WithFailFast(tt.failFast).WithExclude([]string{"vendor"}).WithExcludePaths(backing[:1])
			var results []ecosystems.SCAResult

			err := registry.NativePlugin().BuildDepGraphsFromDir(context.Background(), logger.Nop(), "test", opts, func(result ecosystems.SCAResult) error {
				results = append(results, result)
				return nil
			})

			require.NoError(t, err)
			require.Len(t, results, tt.wantResults)
			assert.Equal(t, []string{"original"}, []string(opts.Global.ExcludePaths))
			assert.Equal(t, []string{"original", "spare1", "spare2", "spare3"}, backing)
			if tt.firstErr != nil {
				assert.ErrorIs(t, results[0].Error, tt.firstErr)
				require.NotNil(t, results[0].ResolverMetadata)
				assert.Equal(t, "cargo", results[0].ResolverMetadata.PluginName)
			}
			if tt.wantSecond {
				assert.Equal(t, []string{"vendor"}, second.capturedExclude)
				wantExcludes := []string{"original"}
				if len(tt.firstResults) > 0 && len(tt.firstResults[0].ProcessedFiles) > 0 {
					wantExcludes = append(wantExcludes, "Cargo.lock")
				}
				assert.Equal(t, wantExcludes, second.capturedExcludePaths)
			} else {
				assert.Nil(t, second.capturedExcludePaths)
			}
		})
	}
}

func TestNativePlugin_CallbackError(t *testing.T) {
	sentinel := errors.New("consumer failed")
	first := &mockPlugin{name: "cargo", results: []ecosystems.SCAResult{{}, {}}}
	second := &mockPlugin{name: "dotnet"}
	registry := &PluginRegistry{plugins: []ecosystems.SCAPlugin{first, second}}
	count := 0

	opts := ecosystems.NewPluginOptions().WithAllProjects(true)
	err := registry.NativePlugin().BuildDepGraphsFromDir(context.Background(), logger.Nop(), "test", opts, func(ecosystems.SCAResult) error {
		count++
		return sentinel
	})

	assert.ErrorIs(t, err, sentinel)
	assert.Equal(t, 1, count)
	assert.Nil(t, second.capturedExcludePaths)
}

func TestNativePlugin_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plugin := &mockPlugin{name: "cargo"}
	registry := &PluginRegistry{plugins: []ecosystems.SCAPlugin{plugin}}

	err := registry.NativePlugin().BuildDepGraphsFromDir(ctx, logger.Nop(), "test", ecosystems.NewPluginOptions(), func(ecosystems.SCAResult) error {
		t.Fatal("canceled invocation emitted a result")
		return nil
	})

	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, plugin.capturedExcludePaths)
}
