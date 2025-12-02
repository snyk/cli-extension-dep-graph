package depgraph

import (
	"bytes"
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
	pluginOptions := scaplugin.Options{
		AllProjects: allProjects,
		Dev:         dev,
	}

	// Generate SBOMs
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
	for i := range findings { // Could be parallelised in future
		data, err := sbomToWorkflowData(ctx, &findings[i], snykClient, logger, remoteRepoURL)
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
	for i := range findings {
		exclusions = append(exclusions, findings[i].FileExclusions...)
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

func sbomToWorkflowData(
	ctx workflow.InvocationContext,
	finding *scaplugin.Finding,
	snykClient *snykclient.SnykClient,
	logger *zerolog.Logger,
	remoteRepoURL string,
) ([]workflow.Data, error) {
	sbomReader := bytes.NewReader(finding.Sbom)

	scans, warnings, err := snykClient.SBOMConvert(ctx.Context(), logger, sbomReader, remoteRepoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SBOM: %w", err)
	}

	logger.Printf("Successfully converted SBOM, warning(s): %d\n", len(warnings))

	depGraphsData, err := extractDepGraphsFromScans(scans, finding.NormalisedTargetFile)
	if err != nil {
		return nil, fmt.Errorf("failed to extract depgraphs from scan results: %w", err)
	}

	if len(depGraphsData) == 0 {
		depGraph, err := emptyDepGraph(finding)
		if err != nil {
			return nil, fmt.Errorf("failed to create empty depgraph: %w", err)
		}

		data, err := workflowDataFromDepGraph(depGraph, finding.NormalisedTargetFile, "")
		if err != nil {
			return nil, fmt.Errorf("failed to create workflow data: %w", err)
		}
		depGraphsData = append(depGraphsData, data)
	}
	return depGraphsData, nil
}

func emptyDepGraph(finding *scaplugin.Finding) (*depgraph.DepGraph, error) {
	if finding.Metadata.PackageManager == "" {
		return nil, fmt.Errorf("found empty PackageManager on finding.Metadata")
	}
	if finding.Metadata.Name == "" {
		return nil, fmt.Errorf("found empty Name on finding.Metadata")
	}
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: finding.Metadata.PackageManager},
		&depgraph.PkgInfo{Name: finding.Metadata.Name, Version: finding.Metadata.Version},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build depgraph: %w", err)
	}
	depGraph := builder.Build()
	return depGraph, nil
}

func extractDepGraphsFromScans(scans []*snykclient.ScanResult, normalisedTargetFile string) ([]workflow.Data, error) {
	var depGraphList []workflow.Data

	for _, scan := range scans {
		// Look for depgraph facts in this scan result
		for _, fact := range scan.Facts {
			if fact.Type != "depGraph" {
				continue
			}

			// ScanResultFact.UnmarshalJSON deserializes fact.Data into *depgraph.DepGraph when type is "depGraph".
			depGraph, ok := fact.Data.(*depgraph.DepGraph)
			if !ok {
				return nil, fmt.Errorf("expected fact.Data to be *depgraph.DepGraph, got %T", fact.Data)
			}
			if depGraph == nil {
				return nil, fmt.Errorf("depGraph is nil for fact with type 'depGraph'")
			}

			data, err := workflowDataFromDepGraph(depGraph, normalisedTargetFile, scan.Identity.TargetFile)
			if err != nil {
				return nil, fmt.Errorf("failed to create workflow data: %w", err)
			}

			depGraphList = append(depGraphList, data)
		}
	}

	return depGraphList, nil
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
