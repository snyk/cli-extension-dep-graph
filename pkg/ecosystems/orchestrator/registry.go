package orchestrator

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/bazel"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/gradle"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/javascript/bun"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

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

func NewDefaultPluginRegistry(ictx workflow.InvocationContext) (*PluginRegistry, error) {
	r := &PluginRegistry{
		ictx:    ictx,
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	// bazel, a dependency of every other plugin because it's a build tool that can build any other language.
	if err := r.register(bazel.Plugin{}, withFeatureFlagCheck(FlagBazelResolver)); err != nil {
		return nil, fmt.Errorf("failed to register bazel plugin: %w", err)
	}
	// javascript
	if err := r.register(bun.Plugin{}, withFeatureFlagCheck(FlagBunResolver), withPluginDependencies("bazel")); err != nil {
		return nil, fmt.Errorf("failed to register bun plugin: %w", err)
	}
	// gradle (opt-in via feature flag)
	if err := r.register(gradle.Plugin{}, withFeatureFlagCheck(FlagNewGradleResolver), withPluginDependencies("bazel")); err != nil {
		return nil, fmt.Errorf("failed to register gradle plugin: %w", err)
	}

	return r, nil
}

func (r *PluginRegistry) ResolveDepgraphs(dir string, opts *ecosystems.SCAPluginOptions) <-chan ecosystems.SCAResult {
	resultsChan := make(chan ecosystems.SCAResult)

	// Clone opts so WithExcludePaths mutations during the loop don't reach into the
	// caller's opts. Other Global fields are shallow-copied; only ExcludePaths is mutated
	// here, so its backing slice is the only one we need to clone.
	localOpts := *opts
	localOpts.Global.ExcludePaths = append(ecosystems.CommaSeparatedString(nil), opts.Global.ExcludePaths...)
	opts = &localOpts

	go func() {
		defer close(resultsChan)

		ctx := r.ictx.Context()
		enhancedLogger := r.ictx.GetEnhancedLogger()

		for _, plugin := range r.plugins {
			select {
			case <-ctx.Done():
				return
			default:
			}

			files := executePluginWithResults(ctx, plugin, enhancedLogger, dir, opts, resultsChan)
			if len(files) > 0 && !opts.Global.AllProjects {
				return
			}
			opts.WithExcludePaths(files)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		executePluginWithResults(ctx, legacy.NewPlugin(r.ictx), enhancedLogger, dir, opts, resultsChan)
	}()

	return resultsChan
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

func executePluginWithResults(
	ctx context.Context,
	plugin ecosystems.SCAPlugin,
	enhancedLogger *zerolog.Logger,
	dir string,
	opts *ecosystems.SCAPluginOptions,
	resultsChan chan ecosystems.SCAResult,
) []string {
	enhancedLogger.Info().Msg(fmt.Sprintf("Executing %s plugin", plugin.GetName()))

	// processedFiles is the deduped union across every emitted result.
	// Plugins attach per-result file lists on SCAResult.ProcessedFiles;
	// the orchestrator unions them here so callers see one flat list
	// per plugin run.
	seen := make(map[string]struct{})
	var processedFiles []string

	err := plugin.BuildDepGraphsFromDir(ctx, logger.NewFromZerolog(enhancedLogger), dir, opts, func(result ecosystems.SCAResult) error {
		for _, p := range result.ProcessedFiles {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			processedFiles = append(processedFiles, p)
		}
		select {
		case resultsChan <- result:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil {
		enhancedLogger.Warn().Err(err).Msg(fmt.Sprintf("%s plugin failed", plugin.GetName()))
		return processedFiles
	}

	return processedFiles
}
