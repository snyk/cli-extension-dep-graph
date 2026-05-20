package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

var legacyCLIWorkflowID = workflow.NewWorkflowIdentifier("legacycli")

const PluginName = "legacycli"

type Resolver struct {
	ictx   workflow.InvocationContext
	ignore []string
}

func (l *Resolver) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir implements [ecosystems.SCAPlugin].
func (l *Resolver) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	_ string,
	opts *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	dgs, err := getDepGraphsFromLegacy(l.ictx, opts, l.ignore)
	if err != nil {
		log.Error(ctx, "failed to resolve dep-graphs from legacy plugins", logger.Err(err))
		return nil, fmt.Errorf("failed to resolve dep-graphs from legacy plugins: %w", err)
	}

	var processed []string
	for _, res := range dgs {
		processed = append(processed, res.ProjectDescriptor.GetTargetFile())
	}

	return &ecosystems.PluginResult{
		Results:        dgs,
		ProcessedFiles: processed,
	}, nil
}

func NewLegacyResolver(ictx workflow.InvocationContext, ignore []string) *Resolver {
	return &Resolver{
		ictx,
		ignore,
	}
}

var _ ecosystems.SCAPlugin = new(Resolver)

// getDepGraphsFromLegacy invokes the legacy CLI workflow with the raw flags and returns parsed results.
func getDepGraphsFromLegacy(
	ictx workflow.InvocationContext,
	opts *ecosystems.SCAPluginOptions,
	ignores []string,
) ([]ecosystems.SCAResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("cannot resolve dependencies without options")
	}

	// if we already processed files, and we're not in all-projects mode, we can skip the fallback
	// TODO: this should be the responsibility of the orchestrator.
	if len(ignores) > 0 && !opts.Global.AllProjects {
		return nil, nil
	}

	data, invocationErr := invokeLegacyCLI(ictx, opts, ignores)
	invocationSucceeded := invocationErr == nil

	// UV-style: get payload once, then one loop over lines—append success or error result per line.
	// Only return a single error when there is no parseable payload (or fatal parse/type failure).
	results, fatalErr := tryBuildResultsFromLegacyPayload(ictx, data, invocationSucceeded)
	if fatalErr != nil {
		return nil, fatalErr
	}
	if len(results) > 0 {
		return results, nil
	}
	if invocationSucceeded {
		return []ecosystems.SCAResult{}, nil
	}

	//nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog
	return nil, legacycli.ExtractLegacyCLIError(invocationErr, data)
}

func invokeLegacyCLI(ictx workflow.InvocationContext, opts *ecosystems.SCAPluginOptions, ignores []string) ([]workflow.Data, error) {
	// Add --print-effective-graph-with-errors for JSONL output with error handling
	cmdArgs := append([]string(nil), opts.Global.RawFlags...)
	cmdArgs = append(cmdArgs, "--print-effective-graph-with-errors")

	// Use --exclude-paths so the legacy CLI matches exact paths rather than
	// basenames. --exclude would incorrectly exclude every manifest that
	// shares a basename with one of the processed files (e.g. all
	// package.json files in a workspace).
	if len(ignores) > 0 {
		cmdArgs = mergeExcludePathsArg(cmdArgs, ignores)
	}

	// Clone config and set the command args
	legacyConfig := ictx.GetConfiguration().Clone()
	legacyConfig.Set(configuration.RAW_CMD_ARGS, cmdArgs)

	// Invoke legacy CLI workflow
	legacyData, err := ictx.GetEngine().InvokeWithConfig(legacyCLIWorkflowID, legacyConfig)
	if err != nil {
		if strings.Contains(err.Error(), "No supported files found") && len(ignores) > 0 {
			return nil, nil
		}
		ictx.GetEnhancedLogger().Error().Err(err).Msg("Legacy CLI workflow returned error")
	}

	return legacyData, err //nolint:wrapcheck // Bubble up error so it can be extracted by caller.
}

// mergeExcludePathsArg appends ignores to the args, merging with any
// user-supplied --exclude-paths value already present in cmdArgs so user
// input is not silently dropped.
func mergeExcludePathsArg(cmdArgs, ignores []string) []string {
	const flag = "--exclude-paths"
	const flagEq = flag + "="

	for i, arg := range cmdArgs {
		if strings.HasPrefix(arg, flagEq) {
			existing := strings.TrimPrefix(arg, flagEq)
			cmdArgs[i] = flagEq + joinNonEmpty(existing, strings.Join(ignores, ","))
			return cmdArgs
		}
		if arg == flag && i+1 < len(cmdArgs) {
			cmdArgs[i+1] = joinNonEmpty(cmdArgs[i+1], strings.Join(ignores, ","))
			return cmdArgs
		}
	}
	return append(cmdArgs, flagEq+strings.Join(ignores, ","))
}

func joinNonEmpty(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return a + "," + b
	}
}

// tryBuildResultsFromLegacyPayload extracts payload from legacyData, parses JSONL, and returns SCAResults.
func tryBuildResultsFromLegacyPayload(
	ictx workflow.InvocationContext,
	legacyData []workflow.Data,
	invocationSucceeded bool,
) ([]ecosystems.SCAResult, error) {
	var bytes []byte
	if len(legacyData) > 0 {
		payload := legacyData[0].GetPayload()
		if payload != nil {
			var ok bool
			bytes, ok = payload.([]byte)
			if !ok && invocationSucceeded {
				return nil, fmt.Errorf("expected []byte payload, got %T", payload)
			}
		}
	}
	if len(bytes) == 0 {
		return nil, nil
	}

	results, parseErr := parseLegacyJSONLToResults(ictx, bytes)
	if parseErr != nil {
		if invocationSucceeded {
			ictx.GetEnhancedLogger().Error().Err(parseErr).Msg("Failed to parse JSONL output")
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
func parseLegacyJSONLToResults(ictx workflow.InvocationContext, bytes []byte) ([]ecosystems.SCAResult, error) {
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
		result, resErr := depGraphOutputToSCAResult(ictx, output)
		if resErr != nil {
			ictx.GetEnhancedLogger().Error().
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
func depGraphOutputToSCAResult(ictx workflow.InvocationContext, output *parsers.DepGraphOutput) (ecosystems.SCAResult, error) {
	result := ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile:    &output.NormalisedTargetFile,
				TargetRuntime: output.TargetRuntime,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           "legacy",
			NormalisedTargetFile: output.NormalisedTargetFile,
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
			ictx.GetEnhancedLogger().Error().
				Str("targetFile", output.NormalisedTargetFile).
				Err(err).
				Msg("Failed to unmarshal depgraph JSON")
			return result, fmt.Errorf("failed to unmarshal depgraph: %w", err)
		}

		result.DepGraph = &dg
		result.ProjectDescriptor.Identity.ProjectType = dg.PkgManager.Name
		result.ProjectDescriptor.Identity.TargetFile = getProjectTargetFileBasedOnType(dg.PkgManager.Name, output.NormalisedTargetFile, output.Workspace != nil)

		if rootPkg := dg.GetRootPkg(); rootPkg != nil {
			result.ProjectDescriptor.Identity.RootComponentName = rootPkg.Info.Name
		}
	}

	return result, nil
}
