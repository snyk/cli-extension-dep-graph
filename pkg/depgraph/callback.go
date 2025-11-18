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
	"github.com/snyk/cli-extension-dep-graph/internal/uv"
	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
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
	return callbackWithDI(ctx, data, uv.NewUvClient())
}

func callbackWithDI(ctx workflow.InvocationContext, _ []workflow.Data, uvClient uv.Client) ([]workflow.Data, error) {
	engine := ctx.GetEngine()
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	logger.Print("DepGraph workflow start")

	// Check if SBOM resolution mode is enabled
	if config.GetBool(FlagUseSBOMResolution) {
		scaPlugins := []scaplugin.ScaPlugin{
			uv.NewUvPlugin(uvClient),
		}
		return handleSBOMResolution(ctx, config, logger, scaPlugins)
	}

	return handleLegacyWorkflow(engine, config, logger)
}

func handleSBOMResolution(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
	scaPlugins []scaplugin.ScaPlugin,
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

	return workflowData, nil
}

func handleLegacyWorkflow(engine workflow.Engine, config configuration.Configuration, logger *zerolog.Logger) ([]workflow.Data, error) {
	argument, outputParser := chooseGraphArgument(config)

	// prepare invocation of the legacy cli
	prepareLegacyFlags(argument, config, logger)

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

func chooseGraphArgument(config configuration.Configuration) (string, parsers.OutputParser) {
	if config.GetBool(FlagPrintEffectiveGraph) {
		return "--print-effective-graph", parsers.NewJSONL()
	}

	return "--print-graph", parsers.NewPlainText()
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

			data.SetMetaData("Content-Location", "uv.lock")
			data.SetMetaData(MetaKeyNormalisedTargetFile, "uv.lock")

			if scan.Identity.Type != "" {
				data.SetMetaData(MetaKeyTargetFileFromPlugin, scan.Identity.Type)
			}

			depGraphList = append(depGraphList, data)
		}
	}

	return depGraphList, nil
}

//nolint:gocyclo // Function contains many conditional flag checks
func prepareLegacyFlags(argument string, cfg configuration.Configuration, logger *zerolog.Logger) {
	cmdArgs := []string{"test", "--json"}
	cmdArgs = append(cmdArgs, argument)

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
