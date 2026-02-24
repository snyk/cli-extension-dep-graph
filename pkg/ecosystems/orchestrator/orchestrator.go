package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	extensionDepgraph "github.com/snyk/cli-extension-dep-graph/pkg/depgraph"
	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pipenv"

	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var legacyCLIWorkflowID = workflow.NewWorkflowIdentifier("legacycli")

// ResolveDepgraphs resolves dependency graphs for a directory by invoking the legacy CLI workflow.
// It accepts a workflow.InvocationContext to provide access to the engine, configuration, and logger.
// Returns a channel of SCAResult structs containing dependency graphs and associated metadata.
func ResolveDepgraphs(ictx workflow.InvocationContext, dir string, configuration ecosystems.SCAPluginOptions) (<-chan ecosystems.SCAResult, error) {
	enhancedLogger := ictx.GetEnhancedLogger()

	pythonResults := resolvePython(ictx.Context(), enhancedLogger, dir, configuration)

	processedFiles := make([]string, 0, len(pythonResults))
	for _, result := range pythonResults {
		processedFiles = append(processedFiles, result.Metadata.TargetFile)
	}

	// Call legacy fallback to get results
	results, err := LegacyFallback(ictx, configuration, processedFiles)
	if err != nil {
		return nil, err
	}

	// Create channel and send all results
	resultsChan := make(chan ecosystems.SCAResult, len(results))
	for _, result := range results {
		resultsChan <- result
	}
	for _, result := range pythonResults {
		resultsChan <- result
	}
	close(resultsChan)

	return resultsChan, nil
}

func resolvePython(ctx context.Context, enhancedLogger *zerolog.Logger, dir string, configuration ecosystems.SCAPluginOptions) []ecosystems.SCAResult {
	logger := logger.NewFromZerolog(enhancedLogger)

	pipResults, err := pip.Plugin{}.BuildDepGraphsFromDir(ctx, logger, dir, &configuration)
	if err != nil {
		enhancedLogger.Warn().Err(err).Msg("pip plugin failed, continuing with other plugins")
	}

	pipenvResults, err := pipenv.Plugin{}.BuildDepGraphsFromDir(ctx, logger, dir, &configuration)
	if err != nil {
		enhancedLogger.Warn().Err(err).Msg("pipenv plugin failed, continuing with other plugins")
	}

	results := make([]ecosystems.SCAResult, 0, len(pipResults)+len(pipenvResults))
	results = append(results, pipResults...)
	results = append(results, pipenvResults...)

	return results
}

// LegacyFallback invokes the legacy CLI workflow with the raw flags and returns parsed results.
func LegacyFallback(ictx workflow.InvocationContext, options ecosystems.SCAPluginOptions, processedFiles []string) ([]ecosystems.SCAResult, error) {
	logger := ictx.GetEnhancedLogger()
	config := ictx.GetConfiguration()
	engine := ictx.GetEngine()

	// Add --print-effective-graph-with-errors for JSONL output with error handling
	cmdArgs := append([]string(nil), options.Global.RawFlags...)
	cmdArgs = append(cmdArgs, "--print-effective-graph-with-errors")

	for _, file := range processedFiles {
		cmdArgs = append(cmdArgs, "--exclude="+file)
	}

	// Clone config and set the command args
	legacyConfig := config.Clone()
	legacyConfig.Set(configuration.RAW_CMD_ARGS, cmdArgs)

	// Invoke legacy CLI workflow (stdout is captured even when the process exits with an error).
	legacyData, err := engine.InvokeWithConfig(legacyCLIWorkflowID, legacyConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Legacy CLI workflow returned error")
	}

	// UV-style: get payload once, then one loop over lines—append success or error result per line.
	// Only return a single error when there is no parseable payload (or fatal parse/type failure).
	results, fatalErr := tryBuildResultsFromLegacyPayload(legacyData, err, ictx, logger)
	if fatalErr != nil {
		return nil, fatalErr
	}
	if len(results) > 0 {
		return results, nil
	}
	if err == nil {
		return []ecosystems.SCAResult{}, nil
	}
	//nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog
	return nil, extensionDepgraph.ExtractLegacyCLIError(err, legacyData)
}

// tryBuildResultsFromLegacyPayload extracts payload from legacyData, parses JSONL, and returns SCAResults.
// Returns (nil, fatalErr) on payload type error or parse failure when invocation succeeded; (results, nil) when we have lines; (nil, nil) when no parseable output.
func tryBuildResultsFromLegacyPayload(legacyData []workflow.Data, invokeErr error, ictx workflow.InvocationContext, logger *zerolog.Logger) ([]ecosystems.SCAResult, error) {
	var bytes []byte
	if len(legacyData) > 0 {
		payload := legacyData[0].GetPayload()
		if payload != nil {
			var ok bool
			bytes, ok = payload.([]byte)
			if !ok && invokeErr == nil {
				return nil, fmt.Errorf("expected []byte payload, got %T", payload)
			}
		}
	}
	if len(bytes) == 0 {
		return nil, nil
	}
	results, parseErr := parseLegacyJSONLToResults(bytes, ictx)
	if parseErr != nil {
		if invokeErr == nil {
			logger.Error().Err(parseErr).Msg("Failed to parse JSONL output")
			return nil, fmt.Errorf("failed to parse legacy output: %w", parseErr)
		}
		return nil, nil
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// parseLegacyJSONLToResults parses JSONL payload and returns SCAResults (one per line). Returns (nil, err) on parse failure, (results, nil) on success, (nil, nil) when no lines.
func parseLegacyJSONLToResults(bytes []byte, ictx workflow.InvocationContext) ([]ecosystems.SCAResult, error) {
	parser := parsers.NewJSONL()
	depGraphOutputs, parseErr := parser.ParseOutput(bytes)
	if parseErr != nil {
		return nil, parseErr
	}
	if len(depGraphOutputs) == 0 {
		return nil, nil
	}
	results := make([]ecosystems.SCAResult, 0, len(depGraphOutputs))
	for i := range depGraphOutputs {
		output := &depGraphOutputs[i]
		result, resErr := depGraphOutputToSCAResult(output, ictx)
		if resErr != nil {
			results = append(results, ecosystems.SCAResult{
				Metadata: ecosystems.Metadata{TargetFile: output.NormalisedTargetFile},
				Error:    resErr,
			})
		} else {
			results = append(results, result)
		}
	}
	return results, nil
}

// depGraphOutputToSCAResult converts a parser output to an SCA result.
func depGraphOutputToSCAResult(output *parsers.DepGraphOutput, ictx workflow.InvocationContext) (ecosystems.SCAResult, error) {
	logger := ictx.GetEnhancedLogger()
	result := ecosystems.SCAResult{
		Metadata: ecosystems.Metadata{
			TargetFile: output.NormalisedTargetFile,
		},
	}

	// If there's an error in the output, parse as ErrorCatalog so os-flows can render it (expected with --print-effective-graph-with-errors).
	// UV-style: one error per result (use first when the JSON API provides multiple).
	if len(output.Error) > 0 {
		if errs, err := snyk_errors.FromJSONAPIErrorBytes(output.Error); err == nil && len(errs) > 0 {
			result.Error = errs[0]
		} else {
			result.Error = errors.New(string(output.Error))
		}
	}

	// Parse the depgraph JSON if present (may be partial even with errors)
	if len(output.DepGraph) > 0 {
		var dg depgraph.DepGraph
		if err := json.Unmarshal(output.DepGraph, &dg); err != nil {
			// JSON parsing failed - this is a real error, not an expected CLI error
			logger.Error().
				Str("targetFile", output.NormalisedTargetFile).
				Err(err).
				Msg("Failed to unmarshal depgraph JSON")
			return result, fmt.Errorf("failed to unmarshal depgraph: %w", err)
		}

		result.DepGraph = &dg

		// Extract runtime from depgraph if available
		if dg.PkgManager.Name != "" {
			result.Metadata.Runtime = dg.PkgManager.Name
		}
	}

	return result, nil
}
