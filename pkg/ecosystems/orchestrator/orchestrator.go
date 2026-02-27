package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pipenv"
)

var legacyCLIWorkflowID = workflow.NewWorkflowIdentifier("legacycli")

// ResolveDepgraphs resolves dependency graphs for a directory by invoking the legacy CLI workflow.
// It accepts a workflow.InvocationContext to provide access to the engine, configuration, and logger.
// Returns a channel of SCAResult structs containing dependency graphs and associated metadata.
func ResolveDepgraphs(ictx workflow.InvocationContext, dir string, opts ecosystems.SCAPluginOptions) (<-chan ecosystems.SCAResult, error) {
	enhancedLogger := ictx.GetEnhancedLogger()

	pythonResult := resolvePython(ictx.Context(), enhancedLogger, dir, opts)

	// Call legacy fallback to get results
	results, err := LegacyFallback(ictx, opts, pythonResult.ProcessedFiles)
	if err != nil {
		return nil, fmt.Errorf("legacy fallback failed: %w", err)
	}

	// Create channel and send all results
	resultsChan := make(chan ecosystems.SCAResult, len(results))
	for _, result := range results {
		resultsChan <- result
	}
	for _, result := range pythonResult.Results {
		resultsChan <- result
	}
	close(resultsChan)

	return resultsChan, nil
}

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

	result.Results = append(result.Results, pipResults.Results...)
	result.Results = append(result.Results, pipenvResults.Results...)
	result.ProcessedFiles = append(result.ProcessedFiles, pipenvResults.ProcessedFiles...)
	result.ProcessedFiles = append(result.ProcessedFiles, pipenvResults.ProcessedFiles...)

	return result
}

// LegacyFallback invokes the legacy CLI workflow with the raw flags and returns parsed results.
func LegacyFallback(ictx workflow.InvocationContext, options ecosystems.SCAPluginOptions, processedFiles []string) ([]ecosystems.SCAResult, error) {
	log := ictx.GetEnhancedLogger()
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

	// Invoke legacy CLI workflow
	legacyData, err := engine.InvokeWithConfig(legacyCLIWorkflowID, legacyConfig)
	if err != nil {
		log.Error().Err(err).Msg("Legacy CLI workflow returned error")
		return nil, fmt.Errorf("legacy CLI workflow error: %w", err)
	}

	if len(legacyData) == 0 {
		log.Warn().Msg("No data returned from legacy workflow")
		return []ecosystems.SCAResult{}, nil
	}

	// Get the payload bytes from the first workflow data
	payload := legacyData[0].GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("expected []byte payload, got %T", payload)
	}

	// Parse the JSONL output
	parser := parsers.NewJSONL()
	depGraphOutputs, err := parser.ParseOutput(bytes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse JSONL output")
		return nil, fmt.Errorf("failed to parse legacy output: %w", err)
	}

	// Convert to SCAResults
	results := make([]ecosystems.SCAResult, 0, len(depGraphOutputs))
	for i := range depGraphOutputs {
		output := &depGraphOutputs[i]
		result, err := depGraphOutputToSCAResult(output, ictx)
		if err != nil {
			log.Error().
				Str("targetFile", output.NormalisedTargetFile).
				Err(err).
				Msg("Failed to convert depgraph output")
			// Continue with error in result
			results = append(results, ecosystems.SCAResult{
				Metadata: ecosystems.Metadata{TargetFile: output.NormalisedTargetFile},
				Error:    err,
			})
		} else {
			results = append(results, result)
		}
	}

	return results, nil
}

// depGraphOutputToSCAResult converts a parser output to an SCA result.
func depGraphOutputToSCAResult(output *parsers.DepGraphOutput, ictx workflow.InvocationContext) (ecosystems.SCAResult, error) {
	log := ictx.GetEnhancedLogger()
	result := ecosystems.SCAResult{
		Metadata: ecosystems.Metadata{
			TargetFile: output.NormalisedTargetFile,
		},
	}

	// If there's an error in the output, include it (expected with --print-effective-graph-with-errors)
	if len(output.Error) > 0 {
		result.Error = errors.New(string(output.Error))
	}

	// Parse the depgraph JSON if present (may be partial even with errors)
	if len(output.DepGraph) > 0 {
		var dg depgraph.DepGraph
		if err := json.Unmarshal(output.DepGraph, &dg); err != nil {
			// JSON parsing failed - this is a real error, not an expected CLI error
			log.Error().
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
