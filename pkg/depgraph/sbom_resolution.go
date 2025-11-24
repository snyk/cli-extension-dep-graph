package depgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/internal/uv"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
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

	pluginOptions := scaplugin.Options{}

	// Generate SBOMs
	findings := []scaplugin.Finding{}
	allProjects := config.GetBool(FlagAllProjects)
	for _, sp := range scaPlugins {
		f, err := sp.BuildFindingsFromDir(inputDir, pluginOptions, logger)
		if err != nil {
			return nil, fmt.Errorf("error building findings: %w", err)
		}
		if allProjects {
			findings = append(findings, f...)
		} else if len(f) > 0 {
			findings = append(findings, f[0])
			break
		}
	}

	remoteRepoURL := config.GetString("remote-repo-url")
	snykClient := snykclient.NewSnykClient(
		ctx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID)

	// Convert SBOMs to workflow.Data
	workflowData := []workflow.Data{}
	for _, f := range findings { // Could be parallelised in future
		data, err := sbomToWorkflowData(f, snykClient, logger, remoteRepoURL)
		if err != nil {
			return nil, fmt.Errorf("error converting SBOM: %w", err)
		}
		workflowData = append(workflowData, data...)
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
	for _, f := range findings {
		exclusions = append(exclusions, f.FileExclusions...)
	}
	return exclusions
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

func sbomToWorkflowData(finding scaplugin.Finding, snykClient *snykclient.SnykClient, logger *zerolog.Logger, remoteRepoURL string) ([]workflow.Data, error) {
	sbomReader := bytes.NewReader(finding.Sbom)

	scans, warnings, err := snykClient.SBOMConvert(context.Background(), logger, sbomReader, remoteRepoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SBOM: %w", err)
	}

	logger.Printf("Successfully converted SBOM, warning(s): %d\n", len(warnings))

	depGraphsData, err := extractDepGraphsFromScans(scans, finding.NormalisedTargetFile)
	if err != nil {
		return nil, fmt.Errorf("failed to extract depgraphs from scan results: %w", err)
	}

	if len(depGraphsData) == 0 {
		return nil, fmt.Errorf("no dependency graphs found in SBOM conversion response")
	}
	return depGraphsData, nil
}

func extractDepGraphsFromScans(scans []*snykclient.ScanResult, targetFile string) ([]workflow.Data, error) {
	var depGraphList []workflow.Data

	for _, scan := range scans {
		// Look for depgraph facts in this scan result
		for _, fact := range scan.Facts {
			if fact.Type != "depGraph" {
				continue
			}
			// Marshal the depgraph data to JSON bytes
			depGraphBytes, err := json.Marshal(fact.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal depgraph data: %w", err)
			}

			// Create workflow data with the depgraph
			data := workflow.NewData(DataTypeID, contentTypeJSON, depGraphBytes)

			data.SetMetaData(contentLocationKey, targetFile)
			data.SetMetaData(MetaKeyNormalisedTargetFile, targetFile)

			if scan.Identity.Type != "" {
				data.SetMetaData(MetaKeyTargetFileFromPlugin, scan.Identity.Type)
			}

			depGraphList = append(depGraphList, data)
		}
	}

	return depGraphList, nil
}
