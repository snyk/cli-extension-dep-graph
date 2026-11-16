package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/gradle"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

func TestNativePlugin_Resolution(t *testing.T) {
	for _, tt := range []struct {
		name         string
		allProjects  bool
		failFast     bool
		firstResults []ecosystems.SCAResult
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
		{
			name: "fail fast result error skips later native", allProjects: true, failFast: true,
			firstResults: []ecosystems.SCAResult{{Error: context.DeadlineExceeded}}, wantResults: 1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first := &mockPlugin{name: "cargo", results: tt.firstResults}
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

func TestNativePlugin_ReturnedError(t *testing.T) {
	setupErr := errors.New("resolver setup failed")
	for _, tt := range []struct {
		name        string
		allProjects bool
		failFast    bool
	}{
		{name: "default"},
		{name: "all projects", allProjects: true},
		{name: "all projects fail fast", allProjects: true, failFast: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first := &mockPlugin{name: "cargo", err: setupErr}
			later := &mockPlugin{name: "uv"}
			registry := &PluginRegistry{plugins: []ecosystems.SCAPlugin{first, later}}
			opts := ecosystems.NewPluginOptions().WithAllProjects(tt.allProjects).WithFailFast(tt.failFast)
			var results []ecosystems.SCAResult

			err := registry.NativePlugin().BuildDepGraphsFromDir(context.Background(), logger.Nop(), "test", opts,
				func(result ecosystems.SCAResult) error { results = append(results, result); return nil })

			assert.ErrorIs(t, err, setupErr)
			assert.ErrorContains(t, err, "running cargo plugin")
			assert.Empty(t, results)
			assert.Nil(t, later.capturedExcludePaths)
		})
	}
}

func TestNativePlugin_CancellationDuringPlugin(t *testing.T) {
	for _, tt := range []struct {
		name      string
		pluginErr error
		want      error
	}{
		{name: "plugin returns nil", want: context.Canceled},
		{name: "plugin returns unrelated error", pluginErr: errors.New("killed"), want: context.Canceled},
		{name: "plugin returns canceled", pluginErr: context.Canceled, want: context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first := &mockPlugin{name: "cargo", err: tt.pluginErr, onRun: cancel}
			later := &mockPlugin{name: "uv"}
			registry := &PluginRegistry{plugins: []ecosystems.SCAPlugin{first, later}}

			err := registry.NativePlugin().BuildDepGraphsFromDir(ctx, logger.Nop(), "test",
				ecosystems.NewPluginOptions().WithAllProjects(true), func(ecosystems.SCAResult) error { return nil })

			assert.ErrorIs(t, err, tt.want)
			assert.Nil(t, later.capturedExcludePaths)
		})
	}
}

func TestNativePlugin_GradleErrorClaimsManifest(t *testing.T) {
	// arrange
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build.gradle"), nil, 0o600))
	t.Setenv("PATH", "")
	legacy := &mockPlugin{name: "legacy"}
	registry := &PluginRegistry{plugins: []ecosystems.SCAPlugin{gradle.NewGradlePlugin(), legacy}}
	var results []ecosystems.SCAResult

	// act
	err := registry.NativePlugin().BuildDepGraphsFromDir(context.Background(), logger.Nop(), dir,
		ecosystems.NewPluginOptions().WithAllProjects(true),
		func(result ecosystems.SCAResult) error { results = append(results, result); return nil })

	// assert
	require.NoError(t, err)
	require.NotEmpty(t, results)
	require.Error(t, results[0].Error)
	require.NotNil(t, results[0].ResolverMetadata)
	assert.Equal(t, "gradle", results[0].ResolverMetadata.PluginName)
	assert.Contains(t, legacy.capturedExcludePaths, "build.gradle")
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

func TestNativePlugin_MissingMetadata(t *testing.T) {
	descriptorTarget := "nested/build.gradle"
	explicitTarget := "settings.gradle"
	existing := &ecosystems.ResolverMetadata{PluginName: "resolver", NormalisedTargetFile: "existing.gradle"}
	for _, tt := range []struct {
		name                           string
		descriptorTarget, optionTarget *string
		metadata                       *ecosystems.ResolverMetadata
		want                           *ecosystems.ResolverMetadata
	}{
		{
			name: "descriptor target wins", descriptorTarget: &descriptorTarget, optionTarget: &explicitTarget,
			want: &ecosystems.ResolverMetadata{PluginName: "gradle", NormalisedTargetFile: descriptorTarget},
		},
		{
			name: "explicit target fallback", optionTarget: &explicitTarget,
			want: &ecosystems.ResolverMetadata{PluginName: "gradle", NormalisedTargetFile: explicitTarget},
		},
		{name: "plugin fallback", want: &ecosystems.ResolverMetadata{PluginName: "gradle", NormalisedTargetFile: "gradle"}},
		{name: "existing metadata preserved", descriptorTarget: &descriptorTarget, metadata: existing, want: existing},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &mockPlugin{name: "gradle", results: []ecosystems.SCAResult{{
				ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{TargetFile: tt.descriptorTarget}},
				ResolverMetadata:  tt.metadata, Error: context.DeadlineExceeded,
			}}}
			laterPlugin := &mockPlugin{name: "cargo"}
			registry := &PluginRegistry{plugins: []ecosystems.SCAPlugin{plugin, laterPlugin}}
			opts := ecosystems.NewPluginOptions().WithAllProjects(true).WithFailFast(true)
			opts.Global.TargetFile = tt.optionTarget
			var got ecosystems.SCAResult

			err := registry.NativePlugin().BuildDepGraphsFromDir(context.Background(), logger.Nop(), "test", opts, func(result ecosystems.SCAResult) error {
				got = result
				return nil
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got.ResolverMetadata)
			assert.ErrorIs(t, got.Error, context.DeadlineExceeded)
			assert.Nil(t, laterPlugin.capturedExcludePaths)
			if tt.metadata != nil {
				assert.Same(t, tt.metadata, got.ResolverMetadata)
			}
		})
	}
}
