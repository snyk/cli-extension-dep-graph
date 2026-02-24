package orchestrator

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/orchestrator/registry"
)

var legacyCLIWorkflowID = workflow.NewWorkflowIdentifier("legacycli")

// ResolveDepgraphs resolves dependency graphs for a directory using registered plugins
// and legacy CLI fallback. It executes matched plugins first, then calls legacy CLI
// for any remaining files not handled by plugins.
// It accepts a workflow.InvocationContext to provide access to the engine, configuration, and logger.
// The registry parameter specifies which plugins are available for use.
// Returns a channel of SCAResult structs containing dependency graphs and associated metadata.
func ResolveDepgraphs(ictx workflow.InvocationContext, pluginRegistry *registry.Registry, dir string, options ecosystems.SCAPluginOptions) (<-chan ecosystems.SCAResult, error) {
	enhancedLogger := ictx.GetEnhancedLogger()

	// Build discovery options from config
	discoveryOpts := registry.BuildDiscoveryOptions(&options)

	// Match plugins to files in the directory
	matches, err := registry.MatchPluginsToFiles(ictx.Context(), pluginRegistry, dir, discoveryOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to match plugins to files: %w", err)
	}

	// Create channel for results
	resultsChan := make(chan ecosystems.SCAResult)

	go func() {
		defer close(resultsChan)

		// Track files handled by plugins for exclusion from legacy CLI
		handledFiles := make([]string, 0, len(matches))

		// Execute matched plugins first
		if len(matches) > 0 {
			enhancedLogger.Info().Int("count", len(matches)).Msg("Executing plugins")

			// Wrap logger for plugin interface
			pluginLogger := logger.NewFromZerolog(enhancedLogger)

			for _, match := range matches {
				enhancedLogger.Info().
					Str("plugin", match.Plugin.Name()).
					Str("targetFile", match.TargetFile).
					Msg("Executing plugin")

				// Create plugin-specific options with target file set
				pluginOptions := options
				pluginOptions.Global.TargetFile = &match.TargetFile

				// Execute the plugin with specific target file
				results, err := match.Plugin.BuildDepGraphsFromDir(ictx.Context(), pluginLogger, dir, &pluginOptions)
				if err != nil {
					enhancedLogger.Error().
						Err(err).
						Str("plugin", match.Plugin.Name()).
						Str("targetFile", match.TargetFile).
						Msg("Plugin execution failed")
					// Send error result
					resultsChan <- ecosystems.SCAResult{
						Metadata: ecosystems.Metadata{TargetFile: match.TargetFile},
						Error:    fmt.Errorf("plugin %s failed: %w", match.Plugin.Name(), err),
					}
					continue
				}

				// Send all results from this plugin and track handled files
				for _, result := range results {
					resultsChan <- result
					handledFiles = append(handledFiles, result.Metadata.TargetFile)
				}
			}
		}

		// Always call legacy CLI for files not handled by plugins
		enhancedLogger.Info().Int("excludedFiles", len(handledFiles)).Msg("Calling legacy CLI fallback")
		legacyResults, err := LegacyFallback(ictx, options, handledFiles)
		if err != nil {
			enhancedLogger.Error().Err(err).Msg("Legacy CLI fallback failed")
			// Send error result
			resultsChan <- ecosystems.SCAResult{
				Error: fmt.Errorf("legacy CLI fallback failed: %w", err),
			}
			return
		}

		// Send all legacy CLI results
		for _, result := range legacyResults {
			resultsChan <- result
		}
	}()

	return resultsChan, nil
}

// LegacyFallback invokes the legacy CLI workflow with the raw flags and returns parsed results.
// excludedFiles is a list of file paths that should be filtered out from the results.
func LegacyFallback(ictx workflow.InvocationContext, options ecosystems.SCAPluginOptions, _ []string) ([]ecosystems.SCAResult, error) {
	log := ictx.GetEnhancedLogger()
	config := ictx.GetConfiguration()
	engine := ictx.GetEngine()

	// Add --print-effective-graph-with-errors for JSONL output with error handling
	cmdArgs := append([]string(nil), options.Global.RawFlags...)
	cmdArgs = append(cmdArgs, "--print-effective-graph-with-errors")

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
	logger := ictx.GetEnhancedLogger()
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
