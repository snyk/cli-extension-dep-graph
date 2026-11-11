package orchestrator

import (
	"context"
	"errors"
	"testing"

	dg "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

func TestResolveDepgraphs_StopsOnNativeErrorWithoutClaims(t *testing.T) {
	ictx := setupMockInvocationContext(t)
	first := &mockPlugin{name: "first", results: []ecosystems.SCAResult{{Error: errors.New("native failure")}}}
	second := &mockPlugin{name: "second", results: []ecosystems.SCAResult{{ProcessedFiles: []string{"second.lock"}}}}
	registry := &PluginRegistry{ictx: ictx}
	require.NoError(t, registry.register(first))
	require.NoError(t, registry.register(second))

	results := collectResults(registry.ResolveDepgraphs(".", ecosystems.NewPluginOptions()))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "native failure")
}

func TestResolveDepgraphs_FailFastStopsLaterPlugins(t *testing.T) {
	registry := &PluginRegistry{ictx: setupMockInvocationContext(t)}
	require.NoError(t, registry.register(&mockPlugin{name: "first", results: []ecosystems.SCAResult{{Error: errors.New("native failure")}}}))
	require.NoError(t, registry.register(&mockPlugin{name: "second", results: []ecosystems.SCAResult{{ProcessedFiles: []string{"second.lock"}}}}))
	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects, opts.Global.FailFast = true, true

	results := collectResults(registry.ResolveDepgraphs(".", opts))

	require.Len(t, results, 1)
	assert.ErrorContains(t, results[0].Error, "native failure")
}

func TestDefaultRegistry_UVAvailableToDefaultCaller(t *testing.T) {
	registry, err := NewDefaultPluginRegistry(setupMockInvocationContextWithConfig(t, func(cfg configuration.Configuration) {
		cfg.Set(FlagUvResolver.Key, true)
	}))
	require.NoError(t, err)

	names := make([]string, 0, len(registry.Plugins()))
	for _, plugin := range registry.Plugins() {
		names = append(names, plugin.GetName())
	}

	assert.Equal(t, []string{"uv", "legacycli"}, names)
}

func TestPipeline_ChannelAndCallbackAdaptersSharePolicy(t *testing.T) {
	cases := []struct {
		name                  string
		first                 ecosystems.SCAResult
		allProjects, failFast bool
		wantResults, wantEnds int
	}{
		{name: "graph without file claims stops", first: ecosystems.SCAResult{DepGraph: &dg.DepGraph{}}, wantResults: 1, wantEnds: 1},
		{name: "scope claim stops", first: ecosystems.SCAResult{ProcessedFiles: []string{"first.lock"}}, wantResults: 1, wantEnds: 1},
		{name: "empty callback continues", wantResults: 2, wantEnds: 2},
		{name: "error stops default", first: ecosystems.SCAResult{Error: errors.New("failure")}, wantResults: 1, wantEnds: 1},
		{name: "all projects continues after error", first: ecosystems.SCAResult{Error: errors.New("failure")}, allProjects: true, wantResults: 2, wantEnds: 3},
		{name: "failfast stops after error", first: ecosystems.SCAResult{Error: errors.New("failure")}, allProjects: true, failFast: true, wantResults: 1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			registry := &PluginRegistry{ictx: setupMockInvocationContext(t)}
			require.NoError(t, registry.register(&mockPlugin{name: "first", results: []ecosystems.SCAResult{tt.first}}))
			require.NoError(t, registry.register(&mockPlugin{name: "second", results: []ecosystems.SCAResult{{ProcessedFiles: []string{"second.lock"}}}}))
			require.NoError(t, registry.register(legacy.NewPlugin(registry.ictx), withPluginDependencies("first", "second")))
			opts := ecosystems.NewPluginOptions()
			opts.Global.AllProjects, opts.Global.FailFast = tt.allProjects, tt.failFast
			var callbackResults []ecosystems.SCAResult
			var ended []string

			err := RunPlugins(context.Background(), registry.Plugins(), logger.Nop(), ".", opts,
				func(_ ecosystems.SCAPlugin, result ecosystems.SCAResult) error {
					callbackResults = append(callbackResults, result)
					return nil
				},
				func(plugin ecosystems.SCAPlugin) error { ended = append(ended, plugin.GetName()); return nil })
			channelResults := collectResults(registry.ResolveDepgraphs(".", opts))

			if tt.failFast {
				var failFast *FailFastError
				require.ErrorAs(t, err, &failFast)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, callbackResults, tt.wantResults)
			assert.Equal(t, callbackResults, channelResults)
			assert.Len(t, ended, tt.wantEnds)
		})
	}
}

func TestPipeline_ProcessedFilesAreDeduplicatedAndCallerOptionsCloned(t *testing.T) {
	first := &mockPlugin{name: "first", results: []ecosystems.SCAResult{
		{ProcessedFiles: []string{"a.lock", "a.lock"}}, {ProcessedFiles: []string{"b.lock", "a.lock"}},
	}}
	second := &mockPlugin{name: "second"}
	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = true
	opts.Global.ExcludePaths = make(ecosystems.CommaSeparatedString, 1, 10)
	opts.Global.ExcludePaths[0] = "user.lock"

	err := RunPlugins(context.Background(), []ecosystems.SCAPlugin{first, second}, logger.Nop(), ".", opts,
		func(ecosystems.SCAPlugin, ecosystems.SCAResult) error { return nil }, nil)

	require.NoError(t, err)
	assert.Equal(t, []string{"user.lock", "a.lock", "b.lock"}, second.capturedExcludePaths)
	assert.Equal(t, ecosystems.CommaSeparatedString{"user.lock"}, opts.Global.ExcludePaths)
	assert.Equal(t, make(ecosystems.CommaSeparatedString, 9), opts.Global.ExcludePaths[:cap(opts.Global.ExcludePaths)][1:])
}

func TestPipeline_CallbackAndLifecycleFailuresStopExecution(t *testing.T) {
	callbackFailure := errors.New("consumer failed")
	setupFailure := errors.New("setup failed")
	cases := []struct {
		name                 string
		setup, callback, end error
		cancel               bool
		want                 error
	}{
		{name: "setup", setup: setupFailure, want: setupFailure},
		{name: "callback", callback: callbackFailure, want: callbackFailure},
		{name: "plugin end", end: callbackFailure, want: callbackFailure},
		{name: "callback cancellation", cancel: true, want: context.Canceled},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first := &mockPlugin{name: "first", err: tt.setup, results: []ecosystems.SCAResult{{}, {}}}
			if tt.setup != nil {
				first.results = nil
			}
			second := &mockPlugin{name: "second"}
			opts := ecosystems.NewPluginOptions()
			opts.Global.AllProjects = true
			callbacks := 0

			err := RunPlugins(ctx, []ecosystems.SCAPlugin{first, second}, logger.Nop(), ".", opts,
				func(ecosystems.SCAPlugin, ecosystems.SCAResult) error {
					callbacks++
					if tt.cancel {
						cancel()
					}
					return tt.callback
				},
				func(ecosystems.SCAPlugin) error { return tt.end })

			require.ErrorIs(t, err, tt.want)
			assert.Zero(t, second.calls)
			if tt.callback != nil || tt.cancel {
				assert.Equal(t, 1, callbacks)
			}
		})
	}
}

func TestRegistry_UVGatesAndInjection(t *testing.T) {
	cases := []struct {
		name          string
		org, explicit bool
		want          []string
	}{
		{name: "disabled injection does not enable", want: []string{"legacycli"}},
		{name: "organization gate", org: true, want: []string{"uv", "legacycli"}},
		{name: "explicit SBOM bridge", explicit: true, want: []string{"uv", "legacycli"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ictx := setupMockInvocationContextWithConfig(t, func(cfg configuration.Configuration) {
				cfg.Set(FlagUvResolver.Key, tt.org)
				cfg.Set("use-sbom-resolution", tt.explicit)
			})

			registry, err := NewPluginRegistry(ictx, WithUVPlugin(&mockPlugin{name: "uv"}))

			require.NoError(t, err)
			var names []string
			for _, plugin := range registry.Plugins() {
				names = append(names, plugin.GetName())
			}
			assert.Equal(t, tt.want, names)
		})
	}
}
