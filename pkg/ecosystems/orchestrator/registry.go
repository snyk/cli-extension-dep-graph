package orchestrator

import (
	"errors"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/remoteconv"
	"github.com/snyk/cli-extension-dep-graph/v2/internal/snykclient"
	internalworkflow "github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/bazel"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/dotnet/nuget"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/gradle"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/bun"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/pnpm"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/python/uv"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/rust/cargo"
)

// bazelPluginName is duplicated here because bazel.pluginName is unexported.
// Used as a dependency declaration for every plugin that should run after
// bazel. Promote to an exported bazel.PluginName if a third caller appears.
const bazelPluginName = "bazel"

type pluginEntry struct {
	plugin       ecosystems.SCAPlugin
	dependencies []string
	skip         bool
}

type PluginRegistry struct {
	ictx    workflow.InvocationContext
	entries []pluginEntry
	plugins []ecosystems.SCAPlugin
}

type RegistryOption func(*registryOptions)

type registryOptions struct{ uvPlugin ecosystems.SCAPlugin }

// WithUVPlugin injects the UV implementation without changing its feature gate.
func WithUVPlugin(plugin ecosystems.SCAPlugin) RegistryOption {
	return func(opts *registryOptions) { opts.uvPlugin = plugin }
}

func NewDefaultPluginRegistry(ictx workflow.InvocationContext) (*PluginRegistry, error) {
	return NewPluginRegistry(ictx)
}

func NewPluginRegistry(ictx workflow.InvocationContext, options ...RegistryOption) (*PluginRegistry, error) {
	var opts registryOptions
	for _, option := range options {
		option(&opts)
	}
	r := &PluginRegistry{
		ictx:    ictx,
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	// bazel, a dependency of every other plugin because it's a build tool that can build any other language.
	if err := r.register(nativePlugin{SCAPlugin: bazel.Plugin{}}, withFeatureFlagCheck(FlagBazelResolver)); err != nil {
		return nil, fmt.Errorf("failed to register bazel plugin: %w", err)
	}
	// javascript
	if err := r.register(nativePlugin{SCAPlugin: bun.Plugin{}}, withFeatureFlagCheck(FlagBunResolver), withPluginDependencies(bazelPluginName)); err != nil {
		return nil, fmt.Errorf("failed to register bun plugin: %w", err)
	}
	if err := r.register(nativePlugin{SCAPlugin: pnpm.Plugin{}}, withFeatureFlagCheck(FlagPnpmResolver), withPluginDependencies(bazelPluginName)); err != nil {
		return nil, fmt.Errorf("failed to register pnpm plugin: %w", err)
	}
	// gradle (opt-in via feature flag)
	cfg := ictx.GetConfiguration()
	normalizeDepsPostHook := gradle.NewNormalizeDepsPostHook(
		ictx.GetNetworkAccess().GetHttpClient(),
		cfg.GetString(configuration.API_URL),
		cfg.GetString(configuration.ORGANIZATION),
	)
	gradlePlugin := gradle.NewGradlePluginWithNormalizeDepsHook(normalizeDepsPostHook)
	if err := r.register(nativePlugin{SCAPlugin: gradlePlugin}, withFeatureFlagCheck(FlagNewGradleResolver), withPluginDependencies(bazelPluginName)); err != nil {
		return nil, fmt.Errorf("failed to register gradle plugin: %w", err)
	}
	// rust
	if err := r.register(nativePlugin{SCAPlugin: cargo.Plugin{}}, withFeatureFlagCheck(FlagCargoResolver), withPluginDependencies(bazelPluginName)); err != nil {
		return nil, fmt.Errorf("failed to register cargo plugin: %w", err)
	}
	// dotnet
	if err := r.register(nativePlugin{SCAPlugin: nuget.Plugin{}}, withFeatureFlagCheck(FlagDotnetResolver), withPluginDependencies(bazelPluginName)); err != nil {
		return nil, fmt.Errorf("failed to register dotnet plugin: %w", err)
	}

	if cfg.GetBool(FlagUvResolver.Key) || cfg.GetBool(internalworkflow.FlagUseSBOMResolution) {
		uvPlugin := opts.uvPlugin
		if uvPlugin == nil {
			client := snykclient.NewSnykClient(ictx.GetNetworkAccess().GetHttpClient(), cfg.GetString(configuration.API_URL), cfg.GetString(configuration.ORGANIZATION))
			converter := remoteconv.NewRemoteSBOMConverter(client, logger.NewFromZerolog(ictx.GetEnhancedLogger()))
			uvPlugin = uv.NewPlugin(uv.NewClient(), converter, cfg.GetString("remote-repo-url"))
		}
		var dependencies []string
		for _, plugin := range r.plugins {
			dependencies = append(dependencies, plugin.GetName())
		}
		if err := r.register(uvPlugin, withPluginDependencies(dependencies...)); err != nil {
			return nil, fmt.Errorf("failed to register uv plugin: %w", err)
		}
	}
	var dependencies []string
	for _, plugin := range r.plugins {
		dependencies = append(dependencies, plugin.GetName())
	}
	if err := r.register(legacy.NewPlugin(ictx), withPluginDependencies(dependencies...)); err != nil {
		return nil, fmt.Errorf("failed to register legacy plugin: %w", err)
	}

	return r, nil
}

// Plugins returns a caller-owned copy of the registered execution order.
func (r *PluginRegistry) Plugins() []ecosystems.SCAPlugin {
	return append([]ecosystems.SCAPlugin(nil), r.plugins...)
}

func (r *PluginRegistry) ResolveDepgraphs(dir string, opts *ecosystems.SCAPluginOptions) <-chan ecosystems.SCAResult {
	results := make(chan ecosystems.SCAResult)
	go func() {
		defer close(results)
		ctx := r.ictx.Context()
		err := RunPlugins(ctx, r.Plugins(), logger.NewFromZerolog(r.ictx.GetEnhancedLogger()), dir, opts,
			func(_ ecosystems.SCAPlugin, result ecosystems.SCAResult) error {
				select {
				case results <- result:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}, nil)
		var failFast *FailFastError
		if err != nil && !errors.As(err, &failFast) {
			select {
			case results <- ecosystems.SCAResult{Error: err}:
			case <-ctx.Done():
			}
		}
	}()
	return results
}

func (r *PluginRegistry) register(plugin ecosystems.SCAPlugin, opts ...registerOpt) error {
	entry := pluginEntry{plugin: plugin}
	for _, opt := range opts {
		opt(r, &entry)
	}

	if entry.skip {
		return nil
	}

	r.entries = append(r.entries, entry)
	sorted := r.sortPlugins()
	if sorted == nil {
		return fmt.Errorf("circular dependency detected involving plugin: %s", plugin.GetName())
	}
	r.plugins = sorted
	return nil
}

func (r *PluginRegistry) sortPlugins() []ecosystems.SCAPlugin {
	if len(r.entries) == 0 {
		return nil
	}

	pluginMap := make(map[string]int)
	for i, entry := range r.entries {
		pluginMap[entry.plugin.GetName()] = i
	}

	inDegree := make([]int, len(r.entries))
	for i, entry := range r.entries {
		for _, dep := range entry.dependencies {
			if _, exists := pluginMap[dep]; exists {
				inDegree[i]++
			}
		}
	}

	queue := make([]int, 0)
	for i, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, i)
		}
	}

	result := make([]ecosystems.SCAPlugin, 0, len(r.entries))

	for len(queue) > 0 {
		idx := queue[0]
		queue = queue[1:]

		result = append(result, r.entries[idx].plugin)

		pluginName := r.entries[idx].plugin.GetName()
		for i, entry := range r.entries {
			for _, dep := range entry.dependencies {
				if dep == pluginName {
					inDegree[i]--
					if inDegree[i] == 0 {
						queue = append(queue, i)
					}
				}
			}
		}
	}

	if len(result) != len(r.entries) {
		return nil
	}

	return result
}
