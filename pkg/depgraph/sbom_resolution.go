package depgraph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	ecosystemslogger "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/uv"
)

func handleSBOMResolution(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Printf("ERROR: failed to determine org id\n")
		return nil, snykclient.NewEmptyOrgError()
	}

	remoteRepoURL := config.GetString("remote-repo-url")
	snykClient := snykclient.NewSnykClient(
		ctx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
	)

	return handleSBOMResolutionDI(
		ctx,
		config,
		logger,
		[]ecosystems.SCAPlugin{
			uv.NewUvPlugin(uv.NewUvClient(), snykClient, remoteRepoURL),
		},
		handleLegacyResolution,
	)
}

//nolint:gocyclo // Complex orchestration logic with multiple flag combinations
func handleSBOMResolutionDI(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
	scaPlugins []ecosystems.SCAPlugin,
	depGraphWorkflowFunc ResolutionHandlerFunc,
) ([]workflow.Data, error) {
	inputDir := config.GetString(configuration.INPUT_DIRECTORY)
	if inputDir == "" {
		inputDir = "."
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Printf("ERROR: failed to determine org id\n")
		return nil, snykclient.NewEmptyOrgError()
	}

	allProjects := config.GetBool(FlagAllProjects)
	forceIncludeWorkspacePackages := config.GetBool(FlagUvWorkspacePackages)

	targetFile := config.GetString(FlagFile)
	dev := config.GetBool(FlagDev)
	strictOutOfSync := true
	if parsedStrictOutOfSync, err := strconv.ParseBool(config.GetString(FlagStrictOutOfSync)); err == nil {
		strictOutOfSync = parsedStrictOutOfSync
	}
	allowOutOfSync := !strictOutOfSync
	exclude := parseExcludeFlag(config.GetString(FlagExclude))
	failFast := config.GetBool(FlagFailFast)
	forceSingleGraph := config.GetBool(FlagForceSingleGraph)

	pluginOptions := ecosystems.NewPluginOptions().
		WithAllProjects(allProjects).
		WithForceIncludeWorkspacePackages(forceIncludeWorkspacePackages).
		WithIncludeDev(dev).
		WithAllowOutOfSync(allowOutOfSync).
		WithExclude(exclude).
		WithFailFast(failFast).
		WithForceSingleGraph(forceSingleGraph)
	if targetFile != "" {
		pluginOptions = pluginOptions.WithTargetFile(targetFile)
	}

	// Generate Results
	pluginLogger := ecosystemslogger.NewFromZerolog(logger)
	results := []ecosystems.SCAResult{}
	var processedFiles []string
	for _, sp := range scaPlugins {
		pluginResult, err := sp.BuildDepGraphsFromDir(
			ctx.Context(),
			pluginLogger,
			inputDir,
			pluginOptions,
		)
		if err != nil {
			return nil, fmt.Errorf("error building results: %w", err)
		}

		if failFast && allProjects {
			for _, result := range pluginResult.Results {
				if result.Error != nil {
					logResultError(logger, result.Metadata.TargetFile, result.Error)
					return nil, createFailFastError(result.Metadata.TargetFile, result.Error)
				}
			}
		}

		results = append(results, pluginResult.Results...)
		processedFiles = append(processedFiles, pluginResult.ProcessedFiles...)
		if !allProjects && len(pluginResult.Results) > 0 {
			// If `allProjects` is false we don't want more than one project
			break
		}
	}

	// Convert Results to workflow.Data
	var workflowData []workflow.Data
	var problemResults []ecosystems.SCAResult
	var err error

	if targetFile != "" && forceIncludeWorkspacePackages {
		// TODO: Using JSONL to output multiple dep graphs in a single workflow.Data object is a workaround
		// to fix outputting the JSON for multiple workflow.Data objects.
		// Currently only the first workflow.Data object is output.
		// This has been reported to the CLI Team and shown in the following test
		// https://github.com/snyk/go-application-framework/pull/559
		workflowData, problemResults, err = combineWorkspaceResultsAsJSONL(logger, results)
	} else {
		workflowData, problemResults, err = processResultsIndividually(logger, results, allProjects)
	}
	if err != nil {
		return nil, err
	}
	if workflowData == nil {
		workflowData = []workflow.Data{}
	}

	totalResults := len(results)

	if totalResults == 0 || allProjects {
		applyProcessedFilesExclusions(config, processedFiles)

		legacyData, err := executeLegacyWorkflow(ctx, config, logger, depGraphWorkflowFunc, results)
		if err != nil {
			return nil, err
		}

		legacyWorkflowData, legacyProblemResults := processLegacyData(logger, legacyData)
		workflowData = append(workflowData, legacyWorkflowData...)
		problemResults = append(problemResults, legacyProblemResults...)

		totalResults += len(legacyData)
	}

	// TODO: This is a temporary implementation for rendering warnings.
	// The long-term plan is for the CLI to handle all warning rendering.
	// This will require extensions to handle `workflow.Data` objects with
	// errors and propagate them upstream rather than rendering them directly.
	// This change will require coordinated updates across extensions to
	// ensure backwards compatibility and avoid breakages.
	outputAnyWarnings(ctx, logger, problemResults, totalResults)

	return workflowData, nil
}

func logResultError(logger *zerolog.Logger, targetFile string, err error) {
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) && snykErr.Detail != "" {
		logger.Printf("Skipping result for %s which errored with: %v (details: %s)", targetFile, err, snykErr.Detail)
	} else {
		logger.Printf("Skipping result for %s which errored with: %v", targetFile, err)
	}
}

func outputAnyWarnings(ctx workflow.InvocationContext, logger *zerolog.Logger, problemResults []ecosystems.SCAResult, totalResults int) {
	if len(problemResults) > 0 {
		message := renderWarningForProblemResults(problemResults, totalResults)

		err := ctx.GetUserInterface().OutputError(fmt.Errorf("%s", message))
		if err != nil {
			logger.Printf("Failed to output warning message: %v", err)
		}
	}
}

func renderWarningForProblemResults(problemResults []ecosystems.SCAResult, totalResults int) string {
	outputMessage := ""
	for _, result := range problemResults {
		outputMessage += fmt.Sprintf("\n%s:", result.Metadata.TargetFile)
		var snykErr snyk_errors.Error
		if errors.As(result.Error, &snykErr) && snykErr.Detail != "" {
			outputMessage += fmt.Sprintf("\n  %s", snykErr.Detail)
		} else {
			outputMessage += "\n  could not process manifest file"
		}
	}
	outputMessage += fmt.Sprintf("\n✗ %d/%d potential projects failed to get dependencies.", len(problemResults), totalResults)

	redStyle := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "9", Dark: "1"})
	return redStyle.Render(outputMessage)
}

// processLegacyData separates successful dependency graphs from errors in the legacy data.
// It returns workflow data containing only valid dependency graphs, while converting
// any errors into problem results that can be reported as warnings.
func processLegacyData(logger *zerolog.Logger, legacyData []workflow.Data) ([]workflow.Data, []ecosystems.SCAResult) {
	workflowData := make([]workflow.Data, 0, len(legacyData))
	problemResults := make([]ecosystems.SCAResult, 0)

	for _, data := range legacyData {
		errList := data.GetErrorList()
		if len(errList) > 0 {
			problemResults = append(problemResults, extractProblemResults(logger, data, errList)...)
			continue
		}
		workflowData = append(workflowData, data)
	}

	return workflowData, problemResults
}

func extractProblemResults(logger *zerolog.Logger, data workflow.Data, errList []snyk_errors.Error) []ecosystems.SCAResult {
	results := make([]ecosystems.SCAResult, 0, len(errList))
	targetFile, metaErr := data.GetMetaData(contentLocationKey)
	if metaErr != nil {
		logger.Printf("Failed to get metadata %s for workflow data: %v", contentLocationKey, metaErr)
		targetFile = "unknown"
	}
	for i := range errList {
		results = append(results, ecosystems.SCAResult{
			Metadata: ecosystems.Metadata{TargetFile: targetFile},
			Error:    errList[i],
		})
	}
	return results
}

// parseExcludeFlag parses a comma-separated exclude flag value into a slice of strings.
func parseExcludeFlag(excludeFlag string) []string {
	if excludeFlag == "" {
		return nil
	}
	parts := strings.Split(excludeFlag, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func applyProcessedFilesExclusions(config configuration.Configuration, processedFiles []string) {
	if len(processedFiles) == 0 {
		return
	}

	exclude := config.GetString(FlagExclude)
	if exclude != "" {
		exclude = fmt.Sprintf("%s,", exclude)
	}
	exclude = fmt.Sprintf("%s%s", exclude, strings.Join(processedFiles, ","))
	config.Set(FlagExclude, exclude)
}

func executeLegacyWorkflow(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
	depGraphWorkflowFunc ResolutionHandlerFunc,
	results []ecosystems.SCAResult,
) ([]workflow.Data, error) {
	legacyConfig := config.Clone()
	legacyConfig.Unset(FlagPrintEffectiveGraph)
	legacyConfig.Set(FlagPrintEffectiveGraphWithErrors, true)

	legacyData, err := depGraphWorkflowFunc(ctx, legacyConfig, logger)
	if err == nil {
		return legacyData, nil
	}

	// Handle exit code 3 (no projects found to test)
	if isExitCode3(err) {
		if len(results) > 0 {
			logger.Printf("No projects found in legacy workflow (exit code 3), continuing with SBOM data only")
			return nil, nil
		}
		// No SBOM results and no legacy projects found, return the error
		return nil, fmt.Errorf("no supported projects detected: %w", err)
	}

	return nil, fmt.Errorf("error handling legacy workflow: %w", err)
}

func combineWorkspaceResultsAsJSONL(logger *zerolog.Logger, results []ecosystems.SCAResult) ([]workflow.Data, []ecosystems.SCAResult, error) {
	if len(results) == 0 {
		return []workflow.Data{}, []ecosystems.SCAResult{}, nil
	}

	var problemResults []ecosystems.SCAResult
	for _, result := range results {
		if result.Error != nil {
			logResultError(logger, result.Metadata.TargetFile, result.Error)
			problemResults = append(problemResults, result)
			return nil, problemResults, result.Error
		}
	}

	data, err := combineWorkspaceDepGraphsAsJSONL(results)
	if err != nil {
		return nil, problemResults, fmt.Errorf("failed to combine dep graphs: %w", err)
	}

	// All dep-graphs are returned as a single workflow.Data item using JSONL because
	// the CLI only returns the first workflow.Data when invoked directly (e.g. `snyk depgraph`).
	// Ideally we would return multiple workflow.Data items, but this is a workaround until
	// the CLI team addresses the underlying issue.
	// Example failing test: https://github.com/snyk/go-application-framework/pull/559
	workflowData := workflow.NewData(DataTypeID, contentTypeJSONL, data)

	targetFile := results[0].Metadata.TargetFile
	workflowData.SetMetaData(contentLocationKey, targetFile)
	workflowData.SetMetaData(MetaKeyNormalisedTargetFile, targetFile)
	workflowData.SetMetaData(MetaKeyTargetFileFromPlugin, targetFile)

	return []workflow.Data{workflowData}, problemResults, nil
}

func processResultsIndividually(logger *zerolog.Logger, results []ecosystems.SCAResult, allProjects bool) ([]workflow.Data, []ecosystems.SCAResult, error) {
	var workflowData []workflow.Data
	var problemResults []ecosystems.SCAResult
	for i := range results {
		result := &results[i]

		if result.Error != nil {
			logResultError(logger, result.Metadata.TargetFile, result.Error)
			problemResults = append(problemResults, *result)

			if !allProjects {
				return nil, problemResults, result.Error
			}

			continue
		}

		data, err := workflowDataFromDepGraph(result)
		if err != nil {
			return nil, problemResults, fmt.Errorf("failed to create workflow data: %w", err)
		}
		workflowData = append(workflowData, data)
	}
	return workflowData, problemResults, nil
}

type jsonlOutputLine struct {
	DepGraph   *depgraph.DepGraph `json:"depGraph"`
	TargetFile string             `json:"targetFile"`
}

func combineWorkspaceDepGraphsAsJSONL(results []ecosystems.SCAResult) ([]byte, error) {
	var lines [][]byte
	for i := range results {
		if results[i].Error != nil {
			continue
		}
		line := jsonlOutputLine{
			DepGraph:   results[i].DepGraph,
			TargetFile: results[i].Metadata.TargetFile,
		}
		b, err := json.Marshal(line)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal depgraph: %w", err)
		}
		lines = append(lines, b)
	}
	combined := bytes.Join(lines, []byte("\n"))
	return combined, nil
}

func workflowDataFromDepGraph(result *ecosystems.SCAResult) (workflow.Data, error) {
	depGraphBytes, err := json.Marshal(result.DepGraph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal depgraph data: %w", err)
	}

	data := workflow.NewData(DataTypeID, contentTypeJSON, depGraphBytes)

	targetFile := result.Metadata.TargetFile
	data.SetMetaData(contentLocationKey, targetFile)
	data.SetMetaData(MetaKeyNormalisedTargetFile, targetFile)
	data.SetMetaData(MetaKeyTargetFileFromPlugin, targetFile)

	return data, nil
}
