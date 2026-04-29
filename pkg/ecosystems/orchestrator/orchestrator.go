package orchestrator

import (
	"context"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pipenv"
)

// ResolveDepgraphs resolves dependency graphs for a directory by invoking the legacy CLI workflow.
// It accepts a workflow.InvocationContext to provide access to the engine, configuration, and logger.
// Returns a channel of SCAResult structs containing dependency graphs and associated metadata.
//
//nolint:gocritic // hugeParam: ensure `options` is not nil
func ResolveDepgraphs(ictx workflow.InvocationContext, dir string, opts ecosystems.SCAPluginOptions) (<-chan ecosystems.SCAResult, error) {
	enhancedLogger := ictx.GetEnhancedLogger()

	pythonResult := resolvePython(ictx.Context(), enhancedLogger, dir, opts)

	// Call legacy fallback to get legacyResults
	legacyResults, err := resolveLegacy(ictx, enhancedLogger, dir, &opts, pythonResult.ProcessedFiles)
	if err != nil {
		return nil, err
	}

	// Create channel and send all results
	resultsChan := make(chan ecosystems.SCAResult, len(legacyResults.Results)+len(pythonResult.Results))
	for _, result := range legacyResults.Results {
		resultsChan <- result
	}
	for _, result := range pythonResult.Results {
		resultsChan <- result
	}
	close(resultsChan)

	return resultsChan, nil
}

func resolveLegacy(
	ictx workflow.InvocationContext,
	enhancedLogger *zerolog.Logger,
	dir string,
	opts *ecosystems.SCAPluginOptions,
	ignores []string,
) (*ecosystems.PluginResult, error) {
	log := logger.NewFromZerolog(enhancedLogger)
	res, err := legacy.NewLegacyResolver(ictx, ignores).BuildDepGraphsFromDir(ictx.Context(), log, dir, opts)
	if err != nil {
		return nil, err //nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog
	}
	return res, nil
}

//nolint:gocritic // hugeParam: ensure `options` is not nil
func resolvePython(ctx context.Context, enhancedLogger *zerolog.Logger, dir string, opts ecosystems.SCAPluginOptions) ecosystems.PluginResult {
	log := logger.NewFromZerolog(enhancedLogger)

	pipResults, err := pip.Plugin{}.BuildDepGraphsFromDir(ctx, log, dir, &opts)
	if err != nil {
		enhancedLogger.Warn().Err(err).Msg("pip plugin failed, continuing with other plugins")
	}

	pipenvResults, err := pipenv.Plugin{}.BuildDepGraphsFromDir(ctx, log, dir, &opts)
	if err != nil {
		enhancedLogger.Warn().Err(err).Msg("pipenv plugin failed, continuing with other plugins")
	}

	result := ecosystems.PluginResult{}

	if pipResults != nil {
		result.Results = append(result.Results, pipResults.Results...)
		result.ProcessedFiles = append(result.ProcessedFiles, pipResults.ProcessedFiles...)
	}
	if pipenvResults != nil {
		result.Results = append(result.Results, pipenvResults.Results...)
		result.ProcessedFiles = append(result.ProcessedFiles, pipenvResults.ProcessedFiles...)
	}

	return result
}
