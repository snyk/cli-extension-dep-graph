package depgraph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/internal/uv"
	ecosystemslogger "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
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
		[]scaplugin.SCAPlugin{
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
	scaPlugins []scaplugin.SCAPlugin,
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

	// TODO(uv):
	// - validate options - we can't have both all-projects and file args
	// - handle various options, including --all-projects, --file,
	//  --internal-uv-get-packages and --exclude
	// - check which other flags we need to handle

	allProjects := config.GetBool(FlagAllProjects)
	uvWorkspacePackages := config.GetBool(FlagUvWorkspacePackages)

	targetFile := config.GetString(FlagFile)
	dev := config.GetBool(FlagDev)
	exclude := parseExcludeFlag(config.GetString(FlagExclude))
	failFast := config.GetBool(FlagFailFast)
	pluginOptions := scaplugin.Options{
		AllProjects:         allProjects,
		UvWorkspacePackages: uvWorkspacePackages,
		TargetFile:          targetFile,
		Dev:                 dev,
		Exclude:             exclude,
		FailFast:            failFast,
	}

	// Generate Findings
	pluginLogger := ecosystemslogger.NewFromZerolog(logger)
	findings := []scaplugin.Finding{}
	for _, sp := range scaPlugins {
		f, err := sp.BuildFindingsFromDir(
			ctx.Context(),
			inputDir,
			&pluginOptions,
			pluginLogger,
		)
		if err != nil {
			return nil, fmt.Errorf("error building findings: %w", err)
		}

		if failFast && allProjects {
			for _, finding := range f {
				if finding.Error != nil {
					logFindingError(logger, finding.LockFile, finding.Error)
					return nil, createFailFastError(finding.LockFile, finding.Error)
				}
			}
		}

		findings = append(findings, f...)
		if !allProjects && len(f) > 0 {
			// If `allProjects` is false we don't want more than one project
			break
		}
	}

	// Convert Findings to workflow.Data
	var workflowData []workflow.Data
	var problemFindings []scaplugin.Finding
	var err error

	if targetFile != "" && uvWorkspacePackages {
		// TODO: Using JSONL to output multiple dep graphs in a single workflow.Data object is a workaround
		// to fix outputting the JSON for multiple workflow.Data objects.
		// Currently only the first workflow.Data object is output.
		// This has been reported to the CLI Team and shown in the following test
		// https://github.com/snyk/go-application-framework/pull/559
		workflowData, problemFindings, err = combineWorkspaceFindingsAsJSONL(logger, findings)
	} else {
		workflowData, problemFindings, err = processFindingsIndividually(logger, findings, allProjects)
	}
	if err != nil {
		return nil, err
	}
	if workflowData == nil {
		workflowData = []workflow.Data{}
	}

	totalFindings := len(findings)

	if totalFindings == 0 || allProjects {
		applyFindingsExclusions(config, findings)

		legacyData, err := executeLegacyWorkflow(ctx, config, logger, depGraphWorkflowFunc, findings)
		if err != nil {
			return nil, err
		}

		legacyWorkflowData, legacyProblemFindings := processLegacyData(logger, legacyData)
		workflowData = append(workflowData, legacyWorkflowData...)
		problemFindings = append(problemFindings, legacyProblemFindings...)

		totalFindings += len(legacyData)
	}

	// TODO: This is a temporary implementation for rendering warnings.
	// The long-term plan is for the CLI to handle all warning rendering.
	// This will require extensions to handle `workflow.Data` objects with
	// errors and propagate them upstream rather than rendering them directly.
	// This change will require coordinated updates across extensions to
	// ensure backwards compatibility and avoid breakages.
	outputAnyWarnings(ctx, logger, problemFindings, totalFindings)

	return workflowData, nil
}

func logFindingError(logger *zerolog.Logger, lockFile string, err error) {
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) && snykErr.Detail != "" {
		logger.Printf("Skipping finding for %s which errored with: %v (details: %s)", lockFile, err, snykErr.Detail)
	} else {
		logger.Printf("Skipping finding for %s which errored with: %v", lockFile, err)
	}
}

func outputAnyWarnings(ctx workflow.InvocationContext, logger *zerolog.Logger, problemFindings []scaplugin.Finding, totalFindings int) {
	if len(problemFindings) > 0 {
		message := renderWarningForProblemFindings(problemFindings, totalFindings)

		err := ctx.GetUserInterface().Output(message + "\n")
		if err != nil {
			logger.Printf("Failed to output warning message: %v", err)
		}
	}
}

func renderWarningForProblemFindings(problemFindings []scaplugin.Finding, totalFindings int) string {
	outputMessage := ""
	for _, finding := range problemFindings {
		outputMessage += fmt.Sprintf("\n%s:", finding.LockFile)
		var snykErr snyk_errors.Error
		if errors.As(finding.Error, &snykErr) && snykErr.Detail != "" {
			outputMessage += fmt.Sprintf("\n  %s", snykErr.Detail)
		} else {
			outputMessage += "\n  could not process manifest file"
		}
	}
	outputMessage += fmt.Sprintf("\n✗ %d/%d potential projects failed to get dependencies.", len(problemFindings), totalFindings)

	redStyle := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "9", Dark: "1"})
	return redStyle.Render(outputMessage)
}

// processLegacyData separates successful dependency graphs from errors in the legacy data.
// It returns workflow data containing only valid dependency graphs, while converting
// any errors into problem findings that can be reported as warnings.
func processLegacyData(logger *zerolog.Logger, legacyData []workflow.Data) ([]workflow.Data, []scaplugin.Finding) {
	workflowData := make([]workflow.Data, 0, len(legacyData))
	problemFindings := make([]scaplugin.Finding, 0)

	for _, data := range legacyData {
		errList := data.GetErrorList()
		if len(errList) > 0 {
			problemFindings = append(problemFindings, extractProblemFindings(logger, data, errList)...)
			continue
		}
		workflowData = append(workflowData, data)
	}

	return workflowData, problemFindings
}

func extractProblemFindings(logger *zerolog.Logger, data workflow.Data, errList []snyk_errors.Error) []scaplugin.Finding {
	findings := make([]scaplugin.Finding, 0, len(errList))
	lockFile, metaErr := data.GetMetaData(contentLocationKey)
	if metaErr != nil {
		logger.Printf("Failed to get metadata %s for workflow data: %v", contentLocationKey, metaErr)
		lockFile = "unknown"
	}
	for i := range errList {
		findings = append(findings, scaplugin.Finding{
			LockFile: lockFile,
			Error:    errList[i],
		})
	}
	return findings
}

func getExclusionsFromFindings(findings []scaplugin.Finding) []string {
	exclusions := make([]string, 0, len(findings))
	for i := range findings {
		exclusions = append(exclusions, findings[i].FileExclusions...)
	}
	return exclusions
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

func applyFindingsExclusions(config configuration.Configuration, findings []scaplugin.Finding) {
	findingsExclusions := getExclusionsFromFindings(findings)
	if len(findingsExclusions) == 0 {
		return
	}

	exclude := config.GetString(FlagExclude)
	if exclude != "" {
		exclude = fmt.Sprintf("%s,", exclude)
	}
	exclude = fmt.Sprintf("%s%s", exclude, strings.Join(findingsExclusions, ","))
	config.Set(FlagExclude, exclude)
}

func executeLegacyWorkflow(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
	depGraphWorkflowFunc ResolutionHandlerFunc,
	findings []scaplugin.Finding,
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
		if len(findings) > 0 {
			logger.Printf("No projects found in legacy workflow (exit code 3), continuing with SBOM data only")
			return nil, nil
		}
		// No SBOM findings and no legacy projects found, return the error
		return nil, fmt.Errorf("no supported projects detected: %w", err)
	}

	return nil, fmt.Errorf("error handling legacy workflow: %w", err)
}

func combineWorkspaceFindingsAsJSONL(logger *zerolog.Logger, findings []scaplugin.Finding) ([]workflow.Data, []scaplugin.Finding, error) {
	if len(findings) == 0 {
		return []workflow.Data{}, []scaplugin.Finding{}, nil
	}

	var problemFindings []scaplugin.Finding
	for i := range findings {
		if findings[i].Error != nil {
			logFindingError(logger, findings[i].LockFile, findings[i].Error)
			problemFindings = append(problemFindings, findings[i])
		}
	}
	data, err := combineWorkspaceDepGraphsAsJSONL(findings)
	if err != nil {
		return nil, problemFindings, fmt.Errorf("failed to combine dep graphs: %w", err)
	}

	workflowData := workflow.NewData(DataTypeID, contentTypeJSONL, data)

	targetFile := findings[0].ManifestFile
	workflowData.SetMetaData(contentLocationKey, targetFile)
	workflowData.SetMetaData(MetaKeyNormalisedTargetFile, targetFile)
	workflowData.SetMetaData(MetaKeyTargetFileFromPlugin, targetFile)

	return []workflow.Data{workflowData}, problemFindings, nil
}

func processFindingsIndividually(logger *zerolog.Logger, findings []scaplugin.Finding, allProjects bool) ([]workflow.Data, []scaplugin.Finding, error) {
	var workflowData []workflow.Data
	var problemFindings []scaplugin.Finding
	for i := range findings {
		finding := &findings[i]

		if finding.Error != nil {
			logFindingError(logger, finding.LockFile, finding.Error)
			problemFindings = append(problemFindings, *finding)

			if !allProjects {
				return nil, problemFindings, finding.Error
			}

			continue
		}

		data, err := workflowDataFromDepGraph(finding)
		if err != nil {
			return nil, problemFindings, fmt.Errorf("failed to create workflow data: %w", err)
		}
		workflowData = append(workflowData, data)
	}
	return workflowData, problemFindings, nil
}

func combineWorkspaceDepGraphsAsJSONL(findings []scaplugin.Finding) ([]byte, error) {
	var lines [][]byte
	for i := range findings {
		if findings[i].Error != nil {
			continue
		}
		b, err := json.Marshal(findings[i].DepGraph)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal depgraph: %w", err)
		}
		lines = append(lines, b)
	}
	combined := bytes.Join(lines, []byte("\n"))
	return combined, nil
}

func workflowDataFromDepGraph(finding *scaplugin.Finding) (workflow.Data, error) {
	depGraphBytes, err := json.Marshal(finding.DepGraph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal depgraph data: %w", err)
	}

	data := workflow.NewData(DataTypeID, contentTypeJSON, depGraphBytes)

	targetFile := finding.ManifestFile
	data.SetMetaData(contentLocationKey, targetFile)
	data.SetMetaData(MetaKeyNormalisedTargetFile, targetFile)
	data.SetMetaData(MetaKeyTargetFileFromPlugin, targetFile)

	return data, nil
}
