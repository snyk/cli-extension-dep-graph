package orchestrator

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/gradle"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/javascript/bun"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

type pluginEntry struct {
	plugin       ecosystems.SCAPlugin
	dependencies []string
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

	// javascript
	if err := r.register(bun.Plugin{}, ""); err != nil {
		return nil, fmt.Errorf("failed to register bun plugin: %w", err)
	}
	// gradle (opt-in via feature flag)
	if err := r.register(gradle.Plugin{}, FlagNewGradleResolver.Key); err != nil {
		return nil, fmt.Errorf("failed to register gradle plugin: %w", err)
	}

	return r, nil
}

func (r *PluginRegistry) ResolveDepgraphs(dir string, opts *ecosystems.SCAPluginOptions) <-chan ecosystems.SCAResult {
	resultsChan := make(chan ecosystems.SCAResult)

	go func() {
		defer close(resultsChan)

		ctx := r.ictx.Context()
		enhancedLogger := r.ictx.GetEnhancedLogger()
		processedFiles := make([]string, 0)

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
			processedFiles = append(processedFiles, files...)
			opts.WithExclude(files)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		executePluginWithResults(ctx, legacy.NewLegacyResolver(r.ictx, processedFiles), enhancedLogger, dir, opts, resultsChan)
	}()

	return resultsChan
}

func (r *PluginRegistry) register(plugin ecosystems.SCAPlugin, flag string, dependencies ...string) error {
	if flag != "" {
		if !r.ictx.GetConfiguration().GetBool(flag) {
			return nil
		}
	}
	r.entries = append(r.entries, pluginEntry{
		plugin:       plugin,
		dependencies: dependencies,
	})
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
	results, err := plugin.BuildDepGraphsFromDir(ctx, logger.NewFromZerolog(enhancedLogger), dir, opts)
	if err != nil {
		enhancedLogger.Warn().Err(err).Msg(fmt.Sprintf("%s plugin failed", plugin.GetName()))
		return nil
	}

	if results != nil {
		for _, result := range results.Results {
			select {
			case resultsChan <- result:
			case <-ctx.Done():
				return nil
			}
		}

		return results.ProcessedFiles
	}

	return nil
}
