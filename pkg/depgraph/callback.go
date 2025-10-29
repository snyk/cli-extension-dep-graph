package depgraph

import (
	_ "embed"
	"fmt"
	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"log"
	"strconv"
)

var (
	legacyWorkflowID = workflow.NewWorkflowIdentifier("legacycli")
)

//go:embed testdata/mock_depgraph.json
var mockDepGraph []byte

func callback(ctx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	engine := ctx.GetEngine()
	config := ctx.GetConfiguration()
	logger := ctx.GetLogger()

	logger.Println("DepGraph workflow start")

	// Check if SBOM resolution mode is enabled
	if config.GetBool(FlagUseSBOMResolution) {
		logger.Println("SBOM resolve mode enabled, returning mock dependency graph")
		data := workflow.NewData(DataTypeID, "application/json", mockDepGraph)
		data.SetMetaData("Content-Location", "uv.lock")
		logger.Println("SBOM resolve mode done, returning mock dependency graph")
		return []workflow.Data{data}, nil
	}

	// prepare invocation of the legacy cli
	prepareLegacyFlags(config, logger)

	legacyData, legacyCLIError := engine.InvokeWithConfig(legacyWorkflowID, config)
	if legacyCLIError != nil {
		return nil, extractLegacyCLIError(legacyCLIError, legacyData)
	}

	snykOutput, _ := legacyData[0].GetPayload().([]byte)

	depGraphs, err := parsers.NewPlainText().ParseOutput(snykOutput)
	if err != nil {
		return nil, fmt.Errorf("error parsing dep graphs: %v", err)
	}
	if len(depGraphs) == 0 {
		return nil, errNoDepGraphsFound
	}

	workflowOutputData := mapToWorkflowData(depGraphs)
	logger.Printf("DepGraph workflow done (extracted %d dependency graphs)", len(workflowOutputData))
	return workflowOutputData, nil
}

func mapToWorkflowData(depGraphs []parsers.DepGraphOutput) []workflow.Data {
	depGraphList := []workflow.Data{}
	for _, depGraph := range depGraphs {
		data := workflow.NewData(DataTypeID, "application/json", depGraph.DepGraph)
		data.SetMetaData("Content-Location", depGraph.DisplayTargetName)
		depGraphList = append(depGraphList, data)
	}
	return depGraphList
}

func prepareLegacyFlags(cfg configuration.Configuration, logger *log.Logger) { //nolint:gocyclo
	cmdArgs := []string{"test", "--print-graph", "--json"}

	if allProjects := cfg.GetBool("all-projects"); allProjects {
		cmdArgs = append(cmdArgs, "--all-projects")
	}

	if cfg.GetBool(FlagFailFast) {
		cmdArgs = append(cmdArgs, "--fail-fast")
	}

	if exclude := cfg.GetString("exclude"); exclude != "" {
		cmdArgs = append(cmdArgs, "--exclude="+exclude)
		logger.Println("Exclude:", exclude)
	}

	if detectionDepth := cfg.GetString(FlagDetectionDepth); detectionDepth != "" {
		cmdArgs = append(cmdArgs, "--detection-depth="+detectionDepth)
		logger.Println("Detection depth:", detectionDepth)
	}

	if file := cfg.GetString(FlagFile); file != "" {
		cmdArgs = append(cmdArgs, "--file="+file)
		logger.Println("File:", file)
	} else {
		if targetDir := cfg.GetString(configuration.INPUT_DIRECTORY); targetDir != "" {
			cmdArgs = append(cmdArgs, targetDir)
			logger.Println("Target directory:", targetDir)
		}
	}

	if cfg.GetBool("unmanaged") {
		cmdArgs = append(cmdArgs, "--unmanaged")
		logger.Println("Is unmanaged: true")
	}

	if cfg.GetBool(configuration.DEBUG) {
		cmdArgs = append(cmdArgs, "--debug")
		logger.Println("Debug: true")
	}

	if cfg.GetBool(FlagDev) {
		cmdArgs = append(cmdArgs, "--dev")
		logger.Println("Dev dependencies: true")
	}

	if cfg.GetBool(FlagPruneRepeatedSubdependencies) {
		cmdArgs = append(cmdArgs, "--prune-repeated-subdependencies")
		logger.Println("Prune repeated sub-dependencies: true")
	}

	if cfg.GetBool(FlagMavenAggregateProject) {
		cmdArgs = append(cmdArgs, "--maven-aggregate-project")
		logger.Println("Ensure all modules are resolvable by the Maven reactor: true")
	}

	if cfg.GetBool(FlagScanUnmanaged) {
		cmdArgs = append(cmdArgs, "--scan-unmanaged")
		logger.Println("Specify an individual JAR, WAR, or AAR file: true")
	}

	if cfg.GetBool(FlagScanAllUnmanaged) {
		cmdArgs = append(cmdArgs, "--scan-all-unmanaged")
		logger.Println("Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder: true")
	}

	if subProject := cfg.GetString(FlagSubProject); subProject != "" {
		cmdArgs = append(cmdArgs, "--sub-project="+subProject)
		logger.Println("Sub-project:", subProject)
	}

	if gradleSubProject := cfg.GetString(FlagGradleSubProject); gradleSubProject != "" {
		cmdArgs = append(cmdArgs, "--gradle-sub-project="+gradleSubProject)
		logger.Println("Gradle sub-project:", gradleSubProject)
	}

	if cfg.GetBool(FlagGradleNormalizeDeps) {
		cmdArgs = append(cmdArgs, "--gradle-normalize-deps")
		logger.Println("Normalize Gradle dependencies: true")
	}

	if cfg.GetBool(FlagAllSubProjects) {
		cmdArgs = append(cmdArgs, "--all-sub-projects")
		logger.Println("Test all sub-projects: true")
	}

	if configurationMatching := cfg.GetString(FlagConfigurationMatching); configurationMatching != "" {
		cmdArgs = append(cmdArgs, "--configuration-matching="+configurationMatching)
		logger.Println("Configuration matching:", configurationMatching)
	}

	if configurationAttributes := cfg.GetString(FlagConfigurationAttributes); configurationAttributes != "" {
		cmdArgs = append(cmdArgs, "--configuration-attributes="+configurationAttributes)
		logger.Println("Configuration attributes:", configurationAttributes)
	}

	if initScript := cfg.GetString(FlagInitScript); initScript != "" {
		cmdArgs = append(cmdArgs, "--init-script="+initScript)
		logger.Println("Init script:", initScript)
	}

	if cfg.GetString(FlagNPMStrictOutOfSync) == "false" {
		cmdArgs = append(cmdArgs, "--strict-out-of-sync=false")
		logger.Println("NPM strict-out-of-sync: false")
	}

	if cfg.GetBool(FlagNugetAssetsProjectName) {
		cmdArgs = append(cmdArgs, "--assets-project-name")
		logger.Println("NuGet assets-project-name: true")
	}

	if file := cfg.GetString(FlagNugetPkgsFolder); file != "" {
		cmdArgs = append(cmdArgs, "--packages-folder="+file)
		logger.Println("NuGet packages-folder: ", file)
	}

	if cfg.GetBool(FlagYarnWorkspaces) {
		cmdArgs = append(cmdArgs, "--yarn-workspaces")
		logger.Println("Yarn Workspaces: true")
	}

	if pyCmd := cfg.GetString(FlagPythonCommand); pyCmd != "" {
		cmdArgs = append(cmdArgs, "--command="+pyCmd)
		logger.Println("Python command:", pyCmd)
	}

	if skipUnresolved := cfg.GetString(FlagPythonSkipUnresolved); skipUnresolved != "" {
		cmdArgs = append(cmdArgs, "--skip-unresolved="+skipUnresolved)
		logger.Println("Python skip unresolved: true")
	}

	if pyPkgManager := cfg.GetString(FlagPythonPackageManager); pyPkgManager != "" {
		cmdArgs = append(cmdArgs, "--package-manager="+pyPkgManager)
		logger.Println("Python package manager:", pyPkgManager)
	}

	if maxDepth := cfg.GetInt(FlagUnmanagedMaxDepth); maxDepth != 0 {
		cmdArgs = append(cmdArgs, "--max-depth="+strconv.Itoa(maxDepth))
	}

	if cfg.GetBool(FlagIncludeProvenance) {
		cmdArgs = append(cmdArgs, "--include-provenance")
		logger.Println("Include provenance: true")
	}

	cfg.Set(configuration.RAW_CMD_ARGS, cmdArgs)
}
