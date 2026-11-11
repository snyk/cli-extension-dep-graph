package orchestrator

import (
	"context"
	"errors"
	"testing"

	dg "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

func TestNativePlugin_ErrorContract(t *testing.T) {
	resolverErr := errors.New("native resolver failed")
	callbackErr := errors.New("consumer stopped")
	cases := []struct {
		name         string
		pluginErr    error
		callbackErr  error
		emitResult   bool
		wantReturned error
		wantResults  int
	}{
		{name: "resolver errors become results", pluginErr: resolverErr, wantResults: 1},
		{name: "consumer errors remain returned", emitResult: true, callbackErr: callbackErr, wantReturned: callbackErr, wantResults: 1},
		{name: "cancellation remains returned", pluginErr: context.Canceled, wantReturned: context.Canceled},
		{name: "deadline remains returned", pluginErr: context.DeadlineExceeded, wantReturned: context.DeadlineExceeded},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &mockPlugin{name: "native", err: tt.pluginErr}
			if tt.emitResult {
				plugin.results = []ecosystems.SCAResult{{}}
			}
			wrapped := nativePlugin{SCAPlugin: plugin}
			var results []ecosystems.SCAResult

			err := wrapped.BuildDepGraphsFromDir(context.Background(), logger.Nop(), ".",
				ecosystems.NewPluginOptions().WithTargetFile("build.gradle"), func(r ecosystems.SCAResult) error {
					results = append(results, r)
					return tt.callbackErr
				})

			require.Len(t, results, tt.wantResults)
			if tt.wantReturned != nil {
				require.ErrorIs(t, err, tt.wantReturned)
				return
			}
			require.NoError(t, err)
			require.ErrorIs(t, results[0].Error, resolverErr)
			require.NotNil(t, results[0].ResolverMetadata)
			assert.Equal(t, "native", results[0].ResolverMetadata.PluginName)
			assert.Equal(t, "build.gradle", results[0].ResolverMetadata.NormalisedTargetFile)
		})
	}
}

func TestPluginRegistry_InjectedPluginRetainsReturnedErrors(t *testing.T) {
	ictx := setupMockInvocationContext(t)
	registry, err := NewDefaultPluginRegistry(ictx)
	require.NoError(t, err)
	pluginErr := errors.New("optional resolver setup failed")
	plugins := registry.Plugins(&mockPlugin{name: "uv", err: pluginErr})
	var results []ecosystems.SCAResult

	err = plugins[0].BuildDepGraphsFromDir(context.Background(), logger.Nop(), ".", ecosystems.NewPluginOptions(), func(r ecosystems.SCAResult) error {
		results = append(results, r)
		return nil
	})

	assert.ErrorIs(t, err, pluginErr)
	assert.Empty(t, results)
}

func TestNativePlugin_NormalizesEmittedMetadata(t *testing.T) {
	failure := errors.New("native emitted failure")
	descriptorTarget := "project/build.gradle"
	cases := []struct {
		name                   string
		descriptorTarget       *string
		explicitTarget         string
		metadata               *ecosystems.ResolverMetadata
		wantTarget, wantPlugin string
	}{
		{
			name: "descriptor before explicit target", descriptorTarget: &descriptorTarget,
			explicitTarget: "explicit.gradle", wantTarget: descriptorTarget, wantPlugin: "native",
		},
		{name: "explicit target fallback", explicitTarget: "explicit.gradle", wantTarget: "explicit.gradle", wantPlugin: "native"},
		{name: "plugin fallback", wantTarget: "native", wantPlugin: "native"},
		{
			name:       "existing metadata preserved",
			metadata:   &ecosystems.ResolverMetadata{PluginName: "existing", NormalisedTargetFile: "existing.gradle"},
			wantTarget: "existing.gradle", wantPlugin: "existing",
		},
		{
			name: "partial metadata filled", descriptorTarget: &descriptorTarget,
			metadata:   &ecosystems.ResolverMetadata{VersionBuildInfo: map[string]string{"version": "1"}},
			wantTarget: descriptorTarget, wantPlugin: "native",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			input := ecosystems.SCAResult{
				DepGraph: &dg.DepGraph{}, Error: failure, ResolverMetadata: tt.metadata, ProcessedFiles: []string{"claimed.lock"},
				ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{TargetFile: tt.descriptorTarget}},
			}
			var originalMetadata ecosystems.ResolverMetadata
			if tt.metadata != nil {
				originalMetadata = *tt.metadata
			}
			plugin := nativePlugin{SCAPlugin: &mockPlugin{name: "native", results: []ecosystems.SCAResult{input}}}
			options := ecosystems.NewPluginOptions()
			if tt.explicitTarget != "" {
				options.WithTargetFile(tt.explicitTarget)
			}
			var results []ecosystems.SCAResult

			err := plugin.BuildDepGraphsFromDir(context.Background(), logger.Nop(), ".", options, func(result ecosystems.SCAResult) error {
				results = append(results, result)
				return nil
			})

			require.NoError(t, err)
			require.Len(t, results, 1)
			require.NotNil(t, results[0].ResolverMetadata)
			assert.Equal(t, tt.wantTarget, results[0].ResolverMetadata.NormalisedTargetFile)
			assert.Equal(t, tt.wantPlugin, results[0].ResolverMetadata.PluginName)
			assert.ErrorIs(t, results[0].Error, failure)
			assert.Same(t, input.DepGraph, results[0].DepGraph)
			assert.Equal(t, input.ProcessedFiles, results[0].ProcessedFiles)
			assert.Equal(t, input.ProjectDescriptor, results[0].ProjectDescriptor)
			if tt.metadata != nil {
				assert.Equal(t, tt.metadata.VersionBuildInfo, results[0].ResolverMetadata.VersionBuildInfo)
				assert.Equal(t, originalMetadata, *tt.metadata)
			}
		})
	}
}
