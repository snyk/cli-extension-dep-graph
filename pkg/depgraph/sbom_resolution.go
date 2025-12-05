package depgraph

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/internal/uv"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func handleSBOMResolution(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	return handleSBOMResolutionDI(
		ctx,
		config,
		logger,
		[]scaplugin.ScaPlugin{
			uv.NewUvPlugin(uv.NewUvClient()),
		},
		handleLegacyResolution,
	)
}

func handleSBOMResolutionDI(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
	scaPlugins []scaplugin.ScaPlugin,
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
	dev := config.GetBool(FlagDev)
	exclude := parseExcludeFlag(config.GetString(FlagExclude))
	pluginOptions := scaplugin.Options{
		AllProjects: allProjects,
		Dev:         dev,
		Exclude:     exclude,
	}

	remoteRepoURL := config.GetString("remote-repo-url")
	snykClient := snykclient.NewSnykClient(
		ctx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
	)
	conversionConfig := scaplugin.NewConversionConfig(remoteRepoURL, snykClient)

	// Generate Findings
	findings := []scaplugin.Finding{}
	for _, sp := range scaPlugins {
		f, err := sp.BuildFindingsFromDir(
			ctx.Context(),
			inputDir,
			&pluginOptions,
			&conversionConfig,
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
			logger.Printf("Skipping finding for %s which errored with: %v", finding.NormalisedTargetFile, finding.Error)
			continue
		}

		data, err := workflowDataFromDepGraph(finding.DepGraph, finding.NormalisedTargetFile, finding.TargetFileFromPlugin)
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

func workflowDataFromDepGraph(depGraph *depgraph.DepGraph, normalisedTargetFile, targetFileFromPlugin string) (workflow.Data, error) {
	depGraphBytes, err := json.Marshal(depGraph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal depgraph data: %w", err)
	}

	data := workflow.NewData(DataTypeID, contentTypeJSON, depGraphBytes)

	data.SetMetaData(contentLocationKey, normalisedTargetFile)
	data.SetMetaData(MetaKeyNormalisedTargetFile, normalisedTargetFile)

	if targetFileFromPlugin != "" {
		data.SetMetaData(MetaKeyTargetFileFromPlugin, targetFileFromPlugin)
	}

	return data, nil
}
