package orchestrator

import (
	"context"
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

type nativePlugin struct {
	plugins []ecosystems.SCAPlugin
}

var _ ecosystems.SCAPlugin = (*nativePlugin)(nil)

// NativePlugin lets callers place another resolver before the legacy fallback
// while retaining the registry's feature gates and dependency order.
func (r *PluginRegistry) NativePlugin() ecosystems.SCAPlugin {
	return &nativePlugin{plugins: r.plugins}
}

func (*nativePlugin) GetName() string          { return "native" }
func (*nativePlugin) DetectionGlobs() []string { return nil }
func (*nativePlugin) InputGlobs() []string     { return []string{ecosystems.AllFilesGlob} }

func (p *nativePlugin) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	dir string,
	opts *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	localOpts := *opts
	localOpts.Global.ExcludePaths = append(ecosystems.CommaSeparatedString(nil), opts.Global.ExcludePaths...)

	for _, plugin := range p.plugins {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("native resolution canceled: %w", err)
		}
		emitted := false
		hadError := false
		var callbackErr error
		var processedFiles []string
		seen := make(map[string]struct{})
		emit := func(result ecosystems.SCAResult) error {
			if callbackErr != nil {
				return callbackErr
			}
			emitted = true
			hadError = hadError || result.Error != nil
			for _, file := range result.ProcessedFiles {
				if _, exists := seen[file]; !exists {
					seen[file] = struct{}{}
					processedFiles = append(processedFiles, file)
				}
			}
			callbackErr = onGraph(result)
			return callbackErr
		}
		log.Info(ctx, fmt.Sprintf("Executing %s plugin", plugin.GetName()))
		err := plugin.BuildDepGraphsFromDir(ctx, log, dir, &localOpts, emit)
		if callbackErr != nil {
			return fmt.Errorf("streaming native result: %w", callbackErr)
		}
		if err != nil {
			if emitErr := emit(ecosystems.SCAResult{
				Error:            err,
				ResolverMetadata: &ecosystems.ResolverMetadata{PluginName: plugin.GetName()},
			}); emitErr != nil {
				return fmt.Errorf("streaming native error: %w", emitErr)
			}
		}
		localOpts.WithExcludePaths(processedFiles)
		if emitted && (!localOpts.Global.AllProjects || (localOpts.Global.FailFast && hadError)) {
			break
		}
	}
	return nil
}
