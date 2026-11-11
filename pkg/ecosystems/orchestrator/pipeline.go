package orchestrator

import (
	"context"
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// FailFastError retains the failed result for output-specific error rendering.
type FailFastError struct{ Result ecosystems.SCAResult }

func (e *FailFastError) Error() string { return e.Result.Error.Error() }
func (e *FailFastError) Unwrap() error { return e.Result.Error }

const scannerContextError = "running scanners: %w"

type pluginRun struct {
	processedFiles []string
	meaningful     bool
	firstError     *FailFastError
}

// RunPlugins owns execution policy; callbacks adapt streamed results to an output.
// onPluginEnd allows outputs such as the monitor JSONL bridge to finish a batch.
func RunPlugins(
	ctx context.Context,
	plugins []ecosystems.SCAPlugin,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
	onGraph func(ecosystems.SCAPlugin, ecosystems.SCAResult) error,
	onPluginEnd func(ecosystems.SCAPlugin) error,
) error {
	opts := *options
	opts.Global.ExcludePaths = append(ecosystems.CommaSeparatedString(nil), options.Global.ExcludePaths...)
	for _, plugin := range plugins {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf(scannerContextError, err)
		}
		run, err := runPlugin(ctx, plugin, log, dir, &opts, onGraph)
		if err != nil {
			return err
		}
		if opts.Global.AllProjects && opts.Global.FailFast && run.firstError != nil {
			return run.firstError
		}
		if onPluginEnd != nil {
			if err := onPluginEnd(plugin); err != nil {
				return fmt.Errorf("finishing %s results: %w", plugin.GetName(), err)
			}
		}
		opts.WithExcludePaths(run.processedFiles)
		if run.meaningful && !opts.Global.AllProjects {
			return nil
		}
	}
	return nil
}

func runPlugin(
	ctx context.Context,
	plugin ecosystems.SCAPlugin,
	log logger.Logger,
	dir string,
	opts *ecosystems.SCAPluginOptions,
	onGraph func(ecosystems.SCAPlugin, ecosystems.SCAResult) error,
) (pluginRun, error) {
	var run pluginRun
	seen := make(map[string]struct{})
	var callbackErr error
	err := plugin.BuildDepGraphsFromDir(ctx, log, dir, opts, func(result ecosystems.SCAResult) error {
		if callbackErr != nil {
			return callbackErr
		}
		if err := ctx.Err(); err != nil {
			callbackErr = fmt.Errorf(scannerContextError, err)
			return callbackErr
		}
		for _, file := range result.ProcessedFiles {
			if _, exists := seen[file]; !exists {
				seen[file] = struct{}{}
				run.processedFiles = append(run.processedFiles, file)
			}
		}
		run.meaningful = run.meaningful || result.DepGraph != nil || result.Error != nil || len(result.ProcessedFiles) > 0
		if result.Error != nil && run.firstError == nil {
			run.firstError = &FailFastError{Result: result}
		}
		callbackErr = onGraph(plugin, result)
		return callbackErr
	})
	if callbackErr != nil {
		return run, fmt.Errorf("emitting %s result: %w", plugin.GetName(), callbackErr)
	}
	if err != nil {
		return run, fmt.Errorf("running %s plugin: %w", plugin.GetName(), err)
	}
	if err := ctx.Err(); err != nil {
		return run, fmt.Errorf(scannerContextError, err)
	}
	return run, nil
}
