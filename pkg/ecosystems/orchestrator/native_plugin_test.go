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
