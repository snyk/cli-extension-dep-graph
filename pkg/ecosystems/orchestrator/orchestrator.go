package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	extensionDepgraph "github.com/snyk/cli-extension-dep-graph/pkg/depgraph"
	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pipenv"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

var legacyCLIWorkflowID = workflow.NewWorkflowIdentifier("legacycli")

// ResolveDepgraphs resolves dependency graphs for a directory by invoking the legacy CLI workflow.
// It accepts a workflow.InvocationContext to provide access to the engine, configuration, and logger.
// Returns a channel of SCAResult structs containing dependency graphs and associated metadata.
//
//nolint:gocritic // hugeParam: ensure `options` is not nil
func ResolveDepgraphs(ictx workflow.InvocationContext, dir string, opts ecosystems.SCAPluginOptions) (<-chan ecosystems.SCAResult, error) {
	enhancedLogger := ictx.GetEnhancedLogger()

	pythonResult := resolvePython(ictx.Context(), enhancedLogger, dir, opts)

	// Call legacy fallback to get results
	results, err := LegacyFallback(ictx, opts, pythonResult.ProcessedFiles)
	if err != nil {
		return nil, err
	}

	// Create channel and send all results
	resultsChan := make(chan ecosystems.SCAResult, len(results)+len(pythonResult.Results))
	for _, result := range results {
		resultsChan <- result
	}
	for _, result := range pythonResult.Results {
		resultsChan <- result
	}
	close(resultsChan)

	return resultsChan, nil
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

	result.Results = append(result.Results, pipResults.Results...)
	result.Results = append(result.Results, pipenvResults.Results...)
	result.ProcessedFiles = append(result.ProcessedFiles, pipResults.ProcessedFiles...)
	result.ProcessedFiles = append(result.ProcessedFiles, pipenvResults.ProcessedFiles...)

	return result
}

// LegacyFallback invokes the legacy CLI workflow with the raw flags and returns parsed results.
func LegacyFallback(
	ictx workflow.InvocationContext,
	//nolint:gocritic // hugeParam: ensure `options` is not nil
	options ecosystems.SCAPluginOptions,
	processedFiles []string,
) ([]ecosystems.SCAResult, error) {
	// if we already processed files, and we're not in all-projects mode, we can skip the fallback
	if len(processedFiles) > 0 && !options.Global.AllProjects {
		return nil, nil
	}

	log := ictx.GetEnhancedLogger()
	config := ictx.GetConfiguration()
	engine := ictx.GetEngine()

	// Add --print-effective-graph-with-errors for JSONL output with error handling
	cmdArgs := append([]string(nil), options.Global.RawFlags...)
	cmdArgs = append(cmdArgs, "--print-effective-graph-with-errors")

	if len(processedFiles) > 0 {
		cmdArgs = append(cmdArgs, "--exclude="+strings.Join(processedFiles, ","))
	}

	// Clone config and set the command args
	legacyConfig := config.Clone()
	legacyConfig.Set(configuration.RAW_CMD_ARGS, cmdArgs)

	// Invoke legacy CLI workflow
	legacyData, err := engine.InvokeWithConfig(legacyCLIWorkflowID, legacyConfig)
	if err != nil {
		if strings.Contains(err.Error(), "No supported files found") && len(processedFiles) > 0 {
			return nil, nil
		}
		log.Error().Err(err).Msg("Legacy CLI workflow returned error")
	}

	// UV-style: get payload once, then one loop over lines—append success or error result per line.
	// Only return a single error when there is no parseable payload (or fatal parse/type failure).
	results, fatalErr := tryBuildResultsFromLegacyPayload(legacyData, err, ictx, log)
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
func tryBuildResultsFromLegacyPayload(
	legacyData []workflow.Data, invokeErr error, ictx workflow.InvocationContext, log *zerolog.Logger,
) ([]ecosystems.SCAResult, error) {
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
	results, parseErr := parseLegacyJSONLToResults(bytes, ictx, log)
	if parseErr != nil {
		if invokeErr == nil {
			log.Error().Err(parseErr).Msg("Failed to parse JSONL output")
			return nil, fmt.Errorf("failed to parse legacy output: %w", parseErr)
		}
		return nil, nil
	}
	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}

// parseLegacyJSONLToResults parses JSONL and returns one SCAResult per line. (nil, err) on parse failure; (nil, nil) when no lines.
func parseLegacyJSONLToResults(bytes []byte, ictx workflow.InvocationContext, log *zerolog.Logger) ([]ecosystems.SCAResult, error) {
	parser := parsers.NewJSONL()
	depGraphOutputs, parseErr := parser.ParseOutput(bytes)
	if parseErr != nil {
		return nil, fmt.Errorf("parse legacy JSONL: %w", parseErr)
	}
	if len(depGraphOutputs) == 0 {
		return nil, nil
	}
	// Convert to SCAResults
	results := make([]ecosystems.SCAResult, 0, len(depGraphOutputs))
	for i := range depGraphOutputs {
		output := &depGraphOutputs[i]
		result, resErr := depGraphOutputToSCAResult(output, ictx)
		if resErr != nil {
			log.Error().
				Str("targetFile", output.NormalisedTargetFile).
				Err(resErr).
				Msg("Failed to convert depgraph output")
			results = append(results, ecosystems.SCAResult{
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						TargetFile: &output.NormalisedTargetFile,
					},
				},
				Error: resErr,
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
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: &output.NormalisedTargetFile,
			},
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
			log.Error().
				Str("targetFile", output.NormalisedTargetFile).
				Err(err).
				Msg("Failed to unmarshal depgraph JSON")
			return result, fmt.Errorf("failed to unmarshal depgraph: %w", err)
		}

		result.DepGraph = &dg

		if dg.PkgManager.Name != "" {
			result.ProjectDescriptor.Identity.Type = dg.PkgManager.Name
			result.ProjectDescriptor.Identity.TargetFile = getProjectTargetFileBasedOnType(dg.PkgManager.Name, output.NormalisedTargetFile, output.Workspace != nil)
			// Extract runtime from depgraph if available
			result.ProjectDescriptor.Identity.TargetRuntime = output.TargetRuntime
		}
	}

	return result, nil
}

// getProjectTargetFileBasedOnType determines if a plugin sets targetFile based on package manager type.
func getProjectTargetFileBasedOnType(projectType, file string, isWorkspace bool) *string {
	switch projectType {
	case "pip":
		_, fileName := path.Split(file)
		// snyk-python-plugin sets targetFile for Pipfile and setup.py, but not for requirements.txt
		if strings.HasSuffix(fileName, "requirements.txt") {
			return nil
		}
		return &file
	case "gradle":
		_, fileName := path.Split(file)
		// snyk-gradle-plugin sets targetFile for build.gradle.kts but not for build.gradle
		if strings.HasSuffix(fileName, "build.gradle.kts") {
			return &file
		}
		return nil
	case "poetry", "gomodules", "golangdep", "nuget", "paket", "composer", "cocoapods", "hex", "swift":
		// These plugins set relative path to provided targetFile
		return &file
	case "npm", "yarn", "pnpm":
		if isWorkspace {
			return &file
		}
		return nil
	case "maven", "sbt", "rubygems":
		// These plugins do not set plugin.targetFile
		return nil
	}
	return nil
}
