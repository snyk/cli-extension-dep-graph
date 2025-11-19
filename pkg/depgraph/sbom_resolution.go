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
			return nil, fmt.Errorf("error building SBOM: %w", err)
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
		data, err := sbomToWorkflowData(f.Sbom, snykClient, logger, remoteRepoURL)
		if err != nil {
			return nil, fmt.Errorf("error converting SBOM: %w", err)
		}
		workflowData = append(workflowData, data...)
	}

	if len(findings) == 0 || allProjects {
		findingsExclusions := getExclusionsFromFindings(findings)

		if len(findingsExclusions) > 0 {
			exclude := config.GetString(FlagExclude)
			if exclude != "" {
				exclude = fmt.Sprintf("%s,", exclude)
			}
			exclude = fmt.Sprintf("%s%s", exclude, strings.Join(findingsExclusions, ","))
			config.Set(FlagExclude, exclude)
		}

		legacyData, err := depGraphWorkflowFunc(ctx, config, logger)
		if err != nil {
			return nil, fmt.Errorf("error handling legacy workflow: %w", err)
		}
		workflowData = append(workflowData, legacyData...)
	}

	return workflowData, nil
}

func getExclusionsFromFindings(findings []scaplugin.Finding) []string {
	exclusions := []string{}
	for _, f := range findings {
		exclusions = append(exclusions, f.FilesProcessed...)
	}
	return exclusions
}

func sbomToWorkflowData(sbomOutput []byte, snykClient *snykclient.SnykClient, logger *zerolog.Logger, remoteRepoURL string) ([]workflow.Data, error) {
	sbomReader := bytes.NewReader(sbomOutput)

	scans, warnings, err := snykClient.SBOMConvert(context.Background(), logger, sbomReader, remoteRepoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SBOM: %w", err)
	}

	logger.Printf("Successfully converted SBOM, warning(s): %d\n", len(warnings))

	depGraphsData, err := extractDepGraphsFromScans(scans)
	if err != nil {
		return nil, fmt.Errorf("failed to extract depgraphs from scan results: %w", err)
	}

	if len(depGraphsData) == 0 {
		return nil, fmt.Errorf("no dependency graphs found in SBOM conversion response")
	}
	return depGraphsData, nil
}

func extractDepGraphsFromScans(scans []*snykclient.ScanResult) ([]workflow.Data, error) {
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

			data.SetMetaData(contentLocationKey, "uv.lock")
			data.SetMetaData(MetaKeyNormalisedTargetFile, "uv.lock")

			if scan.Identity.Type != "" {
				data.SetMetaData(MetaKeyTargetFileFromPlugin, scan.Identity.Type)
			}

			depGraphList = append(depGraphList, data)
		}
	}

	return depGraphList, nil
}
