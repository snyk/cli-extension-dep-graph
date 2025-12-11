package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/internal/uv"
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
	// - handle various options, including --all-projects, --file and --exclude
	// - check which other flags we need to handle e.g. fail-fast

	allProjects := config.GetBool(FlagAllProjects)
	targetFile := config.GetString(FlagFile)
	dev := config.GetBool(FlagDev)
	exclude := parseExcludeFlag(config.GetString(FlagExclude))
	pluginOptions := scaplugin.Options{
		AllProjects: allProjects,
		TargetFile:  targetFile,
		Dev:         dev,
		Exclude:     exclude,
	}

	// Generate Findings
	findings := []scaplugin.Finding{}
	for _, sp := range scaPlugins {
		f, err := sp.BuildFindingsFromDir(
			ctx.Context(),
			inputDir,
			&pluginOptions,
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf("error building findings: %w", err)
		}
		findings = append(findings, f...)
		if !allProjects && len(f) > 0 {
			// If `allProjects` is false we don't want more than one project
			break
		}
	}

	// Convert Findings to workflow.Data
	workflowData := []workflow.Data{}
	for i := range findings { // Could be parallelised in future
		finding := &findings[i]

		if finding.Error != nil {
			logFindingError(logger, finding.LockFile, finding.Error)
			continue
		}

		data, err := workflowDataFromDepGraph(finding)
		if err != nil {
			return nil, fmt.Errorf("failed to create workflow data: %w", err)
		}
		workflowData = append(workflowData, data)
	}

	if len(findings) == 0 || allProjects {
		applyFindingsExclusions(config, findings)

		legacyData, err := executeLegacyWorkflow(ctx, config, logger, depGraphWorkflowFunc, findings)
		if err != nil {
			return nil, err
		}
		if legacyData != nil {
			workflowData = append(workflowData, legacyData...)
		}
	}

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

func getExclusionsFromFindings(findings []scaplugin.Finding) []string {
	exclusions := []string{}
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
	legacyData, err := depGraphWorkflowFunc(ctx, config, logger)
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
