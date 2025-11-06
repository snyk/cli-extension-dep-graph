package depgraph

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/internal/uvclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	contentTypeJSON        = "application/json"
	legacyCLIWorkflowIDStr = "legacycli"
	contentLocationKey     = "Content-Location"
)

//nolint:gochecknoglobals // Workflow identifier needs to be a package-level variable
var legacyWorkflowID = workflow.NewWorkflowIdentifier(legacyCLIWorkflowIDStr)

func callback(ctx workflow.InvocationContext, data []workflow.Data) ([]workflow.Data, error) {
	return callbackWithDI(ctx, data, uvclient.NewUVClient())
}

//nolint:gocyclo // Complexity is acceptable for workflow coordination
func callbackWithDI(ctx workflow.InvocationContext, _ []workflow.Data, uvClient uvclient.UVClient) ([]workflow.Data, error) {
	engine := ctx.GetEngine()
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	logger.Print("DepGraph workflow start")

	// Check if SBOM resolution mode is enabled
	if config.GetBool(FlagUseSBOMResolution) {
		inputDir := config.GetString(configuration.INPUT_DIRECTORY)
		if inputDir == "" {
			inputDir = "."
		}

		sbomOutput, err := uvClient.ExportSBOM(inputDir)
		if err != nil {
			return nil, fmt.Errorf("failed to export SBOM using uv: %w", err)
		}

		orgID := config.GetString(configuration.ORGANIZATION)
		if orgID == "" {
			logger.Printf("ERROR: failed to determine org id\n")
			return nil, snykclient.NewEmptyOrgError()
		}
		remoteRepoURL := config.GetString("remote-repo-url")

		c := snykclient.NewSnykClient(
			ctx.GetNetworkAccess().GetHttpClient(),
			config.GetString(configuration.API_URL),
			orgID)

		sbomReader := bytes.NewReader(sbomOutput)

		scans, warnings, err := c.SBOMConvert(context.Background(), logger, sbomReader, remoteRepoURL)
		if err != nil {
			return nil, err
		}

		logger.Printf("Successfully converted SBOM, warning(s): %d\n", len(warnings))

		depGraphsData, err := extractDepGraphsFromScans(scans)
		if err != nil {
			return nil, fmt.Errorf("failed to extract depgraphs from scan results: %w", err)
		}

		if len(depGraphsData) == 0 {
			return nil, fmt.Errorf("no dependency graphs found in SBOM conversion response")
		}

		logger.Printf("DepGraph workflow done (extracted %d dependency graphs from SBOM)", len(depGraphsData))
		return depGraphsData, nil
	}

	arguments, outputParser := chooseGraphArguments(config)

	// prepare invocation of the legacy cli
	prepareLegacyFlags(arguments, config, logger)

	legacyData, legacyCLIError := engine.InvokeWithConfig(legacyWorkflowID, config)
	if legacyCLIError != nil {
		return nil, extractLegacyCLIError(legacyCLIError, legacyData)
	}

	snykOutput, ok := legacyData[0].GetPayload().([]byte)
	if !ok {
		return nil, fmt.Errorf("failed to get payload from legacy data")
	}

	depGraphs, err := outputParser.ParseOutput(snykOutput)
	if err != nil {
		return nil, fmt.Errorf("error parsing dep graphs: %w", err)
	}
	if len(depGraphs) == 0 {
		return nil, errNoDepGraphsFound
	}

	workflowOutputData := mapToWorkflowData(depGraphs)
	logger.Printf("DepGraph workflow done (extracted %d dependency graphs)", len(workflowOutputData))
	return workflowOutputData, nil
}

func chooseGraphArguments(config configuration.Configuration) ([]string, parsers.OutputParser) {
	if config.GetBool(FlagPrintEffectiveGraph) {
		return []string{"--print-effective-graph"}, parsers.NewJSONL()
	}

	return []string{"--print-graph", "--json"}, parsers.NewPlainText()
}

func mapToWorkflowData(depGraphs []parsers.DepGraphOutput) []workflow.Data {
	depGraphList := []workflow.Data{}
	for _, depGraph := range depGraphs {
		data := workflow.NewData(DataTypeID, contentTypeJSON, depGraph.DepGraph)
		data.SetMetaData(contentLocationKey, depGraph.NormalisedTargetFile)
		data.SetMetaData(MetaKeyNormalisedTargetFile, depGraph.NormalisedTargetFile)
		if depGraph.TargetFileFromPlugin != nil {
			data.SetMetaData(MetaKeyTargetFileFromPlugin, *depGraph.TargetFileFromPlugin)
		}
		if depGraph.Target != nil {
			data.SetMetaData(MetaKeyTarget, string(depGraph.Target))
		}
		depGraphList = append(depGraphList, data)
	}
	return depGraphList
}

func extractDepGraphsFromScans(scans []*snykclient.ScanResult) ([]workflow.Data, error) {
	var depGraphList []workflow.Data

	for _, scan := range scans {
		// Look for depgraph facts in this scan result
		for _, fact := range scan.Facts {
			if fact.Type == "depGraph" {
				// Marshal the depgraph data to JSON bytes
				depGraphBytes, err := json.Marshal(fact.Data)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal depgraph data: %w", err)
				}

				// Create workflow data with the depgraph
				data := workflow.NewData(DataTypeID, "application/json", depGraphBytes)

				data.SetMetaData("Content-Location", "uv.lock")
				data.SetMetaData(MetaKeyNormalisedTargetFile, "uv.lock")

				if scan.Identity.Type != "" {
					data.SetMetaData(MetaKeyTargetFileFromPlugin, scan.Identity.Type)
				}

				depGraphList = append(depGraphList, data)
			}
		}
	}

	return depGraphList, nil
}

//nolint:gocyclo // Function contains many conditional flag checks
func prepareLegacyFlags(arguments []string, cfg configuration.Configuration, logger *zerolog.Logger) {
	cmdArgs := []string{"test"}
	cmdArgs = append(cmdArgs, arguments...)

	if allProjects := cfg.GetBool("all-projects"); allProjects {
		cmdArgs = append(cmdArgs, "--all-projects")
	}

	if cfg.GetBool(FlagFailFast) {
		cmdArgs = append(cmdArgs, "--fail-fast")
	}

	if exclude := cfg.GetString("exclude"); exclude != "" {
		cmdArgs = append(cmdArgs, "--exclude="+exclude)
		logger.Print("Exclude:", exclude)
	}

	if detectionDepth := cfg.GetString(FlagDetectionDepth); detectionDepth != "" {
		cmdArgs = append(cmdArgs, "--detection-depth="+detectionDepth)
		logger.Print("Detection depth:", detectionDepth)
	}

	if file := cfg.GetString(FlagFile); file != "" {
		cmdArgs = append(cmdArgs, "--file="+file)
		logger.Print("File:", file)
	} else {
		if targetDir := cfg.GetString(configuration.INPUT_DIRECTORY); targetDir != "" {
			cmdArgs = append(cmdArgs, targetDir)
			logger.Print("Target directory:", targetDir)
		}
	}

	if cfg.GetBool("unmanaged") {
		cmdArgs = append(cmdArgs, "--unmanaged")
		logger.Print("Is unmanaged: true")
	}

	if cfg.GetBool(configuration.DEBUG) {
		cmdArgs = append(cmdArgs, "--debug")
		logger.Print("Debug: true")
	}

	if cfg.GetBool(FlagDev) {
		cmdArgs = append(cmdArgs, "--dev")
		logger.Print("Dev dependencies: true")
	}

	if cfg.GetBool(FlagPruneRepeatedSubdependencies) {
		cmdArgs = append(cmdArgs, "--prune-repeated-subdependencies")
		logger.Print("Prune repeated sub-dependencies: true")
	}

	if cfg.GetBool(FlagMavenAggregateProject) {
		cmdArgs = append(cmdArgs, "--maven-aggregate-project")
		logger.Print("Ensure all modules are resolvable by the Maven reactor: true")
	}

	if cfg.GetBool(FlagScanUnmanaged) {
		cmdArgs = append(cmdArgs, "--scan-unmanaged")
		logger.Print("Specify an individual JAR, WAR, or AAR file: true")
	}

	if cfg.GetBool(FlagScanAllUnmanaged) {
		cmdArgs = append(cmdArgs, "--scan-all-unmanaged")
		logger.Print("Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder: true")
	}

	if subProject := cfg.GetString(FlagSubProject); subProject != "" {
		cmdArgs = append(cmdArgs, "--sub-project="+subProject)
		logger.Print("Sub-project:", subProject)
	}

	if gradleSubProject := cfg.GetString(FlagGradleSubProject); gradleSubProject != "" {
		cmdArgs = append(cmdArgs, "--gradle-sub-project="+gradleSubProject)
		logger.Print("Gradle sub-project:", gradleSubProject)
	}

	if cfg.GetBool(FlagGradleNormalizeDeps) {
		cmdArgs = append(cmdArgs, "--gradle-normalize-deps")
		logger.Print("Normalize Gradle dependencies: true")
	}

	if cfg.GetBool(FlagAllSubProjects) {
		cmdArgs = append(cmdArgs, "--all-sub-projects")
		logger.Print("Test all sub-projects: true")
	}

	if configurationMatching := cfg.GetString(FlagConfigurationMatching); configurationMatching != "" {
		cmdArgs = append(cmdArgs, "--configuration-matching="+configurationMatching)
		logger.Print("Configuration matching:", configurationMatching)
	}

	if configurationAttributes := cfg.GetString(FlagConfigurationAttributes); configurationAttributes != "" {
		cmdArgs = append(cmdArgs, "--configuration-attributes="+configurationAttributes)
		logger.Print("Configuration attributes:", configurationAttributes)
	}

	if initScript := cfg.GetString(FlagInitScript); initScript != "" {
		cmdArgs = append(cmdArgs, "--init-script="+initScript)
		logger.Print("Init script:", initScript)
	}

	if cfg.GetString(FlagNPMStrictOutOfSync) == "false" {
		cmdArgs = append(cmdArgs, "--strict-out-of-sync=false")
		logger.Print("NPM strict-out-of-sync: false")
	}

	if cfg.GetBool(FlagNugetAssetsProjectName) {
		cmdArgs = append(cmdArgs, "--assets-project-name")
		logger.Print("NuGet assets-project-name: true")
	}

	if file := cfg.GetString(FlagNugetPkgsFolder); file != "" {
		cmdArgs = append(cmdArgs, "--packages-folder="+file)
		logger.Print("NuGet packages-folder: ", file)
	}

	if cfg.GetBool(FlagYarnWorkspaces) {
		cmdArgs = append(cmdArgs, "--yarn-workspaces")
		logger.Print("Yarn Workspaces: true")
	}

	if pyCmd := cfg.GetString(FlagPythonCommand); pyCmd != "" {
		cmdArgs = append(cmdArgs, "--command="+pyCmd)
		logger.Print("Python command:", pyCmd)
	}

	if skipUnresolved := cfg.GetString(FlagPythonSkipUnresolved); skipUnresolved != "" {
		cmdArgs = append(cmdArgs, "--skip-unresolved="+skipUnresolved)
		logger.Print("Python skip unresolved: true")
	}

	if pyPkgManager := cfg.GetString(FlagPythonPackageManager); pyPkgManager != "" {
		cmdArgs = append(cmdArgs, "--package-manager="+pyPkgManager)
		logger.Print("Python package manager:", pyPkgManager)
	}

	if maxDepth := cfg.GetInt(FlagUnmanagedMaxDepth); maxDepth != 0 {
		cmdArgs = append(cmdArgs, "--max-depth="+strconv.Itoa(maxDepth))
	}

	if cfg.GetBool(FlagIncludeProvenance) {
		cmdArgs = append(cmdArgs, "--include-provenance")
		logger.Print("Include provenance: true")
	}

	if cfg.GetBool(FlagDotnetRuntimeResolution) {
		cmdArgs = append(cmdArgs, "--dotnet-runtime-resolution")
		logger.Print("Dotnet runtime resolution: true")
	}

	if tf := cfg.GetString(FlagDotnetTargetFramework); tf != "" {
		cmdArgs = append(cmdArgs, "--dotnet-target-framework="+tf)
		logger.Print("Dotnet target framework:", tf)
	}

	cfg.Set(configuration.RAW_CMD_ARGS, cmdArgs)
}
