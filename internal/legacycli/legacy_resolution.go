package legacycli

import (
	"fmt"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/depgraph/parsers"
)

const (
	printGraphCliArg                 = "--print-graph"
	printOutputJsonlWithErrorsCliArg = "--print-output-jsonl-with-errors"
)

var legacyWorkflowID = gafworkflow.NewWorkflowIdentifier(workflow.LegacyCLIWorkflowIDStr)

func HandleLegacyResolution(ctx gafworkflow.InvocationContext, config configuration.Configuration, logger *zerolog.Logger) ([]gafworkflow.Data, error) {
	depGraphs, err := InvokeLegacy(ctx, config, logger)
	if err != nil {
		return nil, err
	}

	workflowOutputData := MapToWorkflowData(depGraphs, logger)
	logger.Printf("DepGraph workflow done (extracted %d dependency graphs)", len(workflowOutputData))
	return workflowOutputData, nil
}

// InvokeLegacy invokes the legacy CLI workflow and parses its output, returning the parsed
// dep-graph outputs. Returns ErrNoDepGraphsFound when the invocation succeeds but produces no
// graphs.
func InvokeLegacy(ctx gafworkflow.InvocationContext, config configuration.Configuration, logger *zerolog.Logger) ([]parsers.DepGraphOutput, error) {
	engine := ctx.GetEngine()
	argument, outputParser := ChooseGraphArgument(config)

	PrepareLegacyFlags(argument, config, logger)

	legacyData, legacyCLIError := engine.InvokeWithConfig(legacyWorkflowID, config)
	if legacyCLIError != nil {
		return nil, ExtractLegacyCLIError(legacyCLIError, legacyData)
	}

	if len(legacyData) == 0 {
		return nil, ErrNoDepGraphsFound
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
		return nil, ErrNoDepGraphsFound
	}

	return depGraphs, nil
}

func ChooseGraphArgument(config configuration.Configuration) (string, parsers.OutputParser) {
	if config.GetBool(workflow.FlagPrintEffectiveGraph) {
		return "--print-effective-graph", parsers.NewJSONL()
	}

	if config.GetBool(workflow.FlagPrintEffectiveGraphWithErrors) {
		return "--print-effective-graph-with-errors", parsers.NewJSONL()
	}

	if config.GetBool(workflow.FlagPrintOutputJsonlWithErrors) {
		return printGraphCliArg, parsers.NewJSONL()
	}

	return printGraphCliArg, parsers.NewPlainText()
}

func MapToWorkflowData(depGraphs []parsers.DepGraphOutput, logger *zerolog.Logger) []gafworkflow.Data {
	depGraphList := make([]gafworkflow.Data, 0, len(depGraphs))
	for i := range depGraphs {
		depGraph := &depGraphs[i]
		data := gafworkflow.NewData(workflow.DataTypeID, workflow.ContentTypeJSON, depGraph.DepGraph)
		data.SetMetaData(workflow.ContentLocationKey, depGraph.NormalisedTargetFile)
		data.SetMetaData(workflow.MetaKeyNormalisedTargetFile, depGraph.NormalisedTargetFile)
		if depGraph.TargetFileFromPlugin != nil {
			data.SetMetaData(workflow.MetaKeyTargetFileFromPlugin, *depGraph.TargetFileFromPlugin)
		}
		if depGraph.Target != nil {
			data.SetMetaData(workflow.MetaKeyTarget, string(depGraph.Target))
		}
		if depGraph.Error != nil {
			snykErrors, err := snyk_errors.FromJSONAPIErrorBytes(depGraph.Error)
			if err != nil {
				logger.Printf("failed to parse error from depgraph output: %v", err)
			} else {
				for i := range len(snykErrors) {
					data.AddError(snykErrors[i])
				}
			}
		}
		depGraphList = append(depGraphList, data)
	}
	return depGraphList
}

//nolint:gocyclo // Function contains many conditional flag checks
func PrepareLegacyFlags(argument string, cfg configuration.Configuration, logger *zerolog.Logger) {
	cmdArgs := []string{"test", "--json"}
	cmdArgs = append(cmdArgs, argument)

	if allProjects := cfg.GetBool("all-projects"); allProjects {
		cmdArgs = append(cmdArgs, "--all-projects")
	}

	if cfg.GetBool(workflow.FlagPrintOutputJsonlWithErrors) {
		cmdArgs = append(cmdArgs, printOutputJsonlWithErrorsCliArg)
	}

	if cfg.GetBool(workflow.FlagFailFast) {
		cmdArgs = append(cmdArgs, "--fail-fast")
	}

	if exclude := cfg.GetString("exclude"); exclude != "" {
		cmdArgs = append(cmdArgs, "--exclude="+exclude)
		logger.Print("Exclude:", exclude)
	}

	if excludePaths := cfg.GetString(workflow.FlagExcludePaths); excludePaths != "" {
		cmdArgs = append(cmdArgs, "--exclude-paths="+excludePaths)
		logger.Print("Exclude paths:", excludePaths)
	}

	if detectionDepth := cfg.GetString(workflow.FlagDetectionDepth); detectionDepth != "" {
		cmdArgs = append(cmdArgs, "--detection-depth="+detectionDepth)
		logger.Print("Detection depth:", detectionDepth)
	}

	if file := cfg.GetString(workflow.FlagFile); file != "" {
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

	if cfg.GetBool(workflow.FlagDev) {
		cmdArgs = append(cmdArgs, "--dev")
		logger.Print("Dev dependencies: true")
	}

	if cfg.GetBool(workflow.FlagPruneRepeatedSubdependencies) {
		cmdArgs = append(cmdArgs, "--prune-repeated-subdependencies")
		logger.Print("Prune repeated sub-dependencies: true")
	}

	if cfg.GetBool(workflow.FlagMavenAggregateProject) {
		cmdArgs = append(cmdArgs, "--maven-aggregate-project")
		logger.Print("Ensure all modules are resolvable by the Maven reactor: true")
	}

	if cfg.GetBool(workflow.FlagMavenSkipWrapper) {
		cmdArgs = append(cmdArgs, "--maven-skip-wrapper")
		logger.Print("Use system Maven instead of the Maven wrapper: true")
	}

	if cfg.GetBool(workflow.FlagScanUnmanaged) {
		cmdArgs = append(cmdArgs, "--scan-unmanaged")
		logger.Print("Specify an individual JAR, WAR, or AAR file: true")
	}

	if cfg.GetBool(workflow.FlagScanAllUnmanaged) {
		cmdArgs = append(cmdArgs, "--scan-all-unmanaged")
		logger.Print("Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder: true")
	}

	if subProject := cfg.GetString(workflow.FlagSubProject); subProject != "" {
		cmdArgs = append(cmdArgs, "--sub-project="+subProject)
		logger.Print("Sub-project:", subProject)
	}

	if gradleSubProject := cfg.GetString(workflow.FlagGradleSubProject); gradleSubProject != "" {
		cmdArgs = append(cmdArgs, "--gradle-sub-project="+gradleSubProject)
		logger.Print("Gradle sub-project:", gradleSubProject)
	}

	if cfg.GetBool(workflow.FlagGradleNormalizeDeps) {
		cmdArgs = append(cmdArgs, "--gradle-normalize-deps")
		logger.Print("Normalize Gradle dependencies: true")
	}

	if cfg.GetBool(workflow.FlagAllSubProjects) {
		cmdArgs = append(cmdArgs, "--all-sub-projects")
		logger.Print("Test all sub-projects: true")
	}

	if configurationMatching := cfg.GetString(workflow.FlagConfigurationMatching); configurationMatching != "" {
		cmdArgs = append(cmdArgs, "--configuration-matching="+configurationMatching)
		logger.Print("Configuration matching:", configurationMatching)
	}

	if configurationAttributes := cfg.GetString(workflow.FlagConfigurationAttributes); configurationAttributes != "" {
		cmdArgs = append(cmdArgs, "--configuration-attributes="+configurationAttributes)
		logger.Print("Configuration attributes:", configurationAttributes)
	}

	if initScript := cfg.GetString(workflow.FlagInitScript); initScript != "" {
		cmdArgs = append(cmdArgs, "--init-script="+initScript)
		logger.Print("Init script:", initScript)
	}

	strictOutOfSync := true
	if parsedStrictOutOfSync, err := strconv.ParseBool(cfg.GetString(workflow.FlagStrictOutOfSync)); err == nil {
		strictOutOfSync = parsedStrictOutOfSync
	}
	if !strictOutOfSync {
		cmdArgs = append(cmdArgs, "--strict-out-of-sync=false")
		logger.Print("strict-out-of-sync: false")
	}

	if cfg.GetBool(workflow.FlagNugetAssetsProjectName) {
		cmdArgs = append(cmdArgs, "--assets-project-name")
		logger.Print("NuGet assets-project-name: true")
	}

	if file := cfg.GetString(workflow.FlagNugetPkgsFolder); file != "" {
		cmdArgs = append(cmdArgs, "--packages-folder="+file)
		logger.Print("NuGet packages-folder: ", file)
	}

	if cfg.GetBool(workflow.FlagYarnWorkspaces) {
		cmdArgs = append(cmdArgs, "--yarn-workspaces")
		logger.Print("Yarn Workspaces: true")
	}

	if pyCmd := cfg.GetString(workflow.FlagPythonCommand); pyCmd != "" {
		cmdArgs = append(cmdArgs, "--command="+pyCmd)
		logger.Print("Python command:", pyCmd)
	}

	if skipUnresolved := cfg.GetString(workflow.FlagPythonSkipUnresolved); skipUnresolved != "" {
		cmdArgs = append(cmdArgs, "--skip-unresolved="+skipUnresolved)
		logger.Print("Python skip unresolved: true")
	}

	if pyPkgManager := cfg.GetString(workflow.FlagPythonPackageManager); pyPkgManager != "" {
		cmdArgs = append(cmdArgs, "--package-manager="+pyPkgManager)
		logger.Print("Python package manager:", pyPkgManager)
	}

	if maxDepth := cfg.GetInt(workflow.FlagUnmanagedMaxDepth); maxDepth != 0 {
		cmdArgs = append(cmdArgs, "--max-depth="+strconv.Itoa(maxDepth))
	}

	if cfg.GetBool(workflow.FlagIncludeProvenance) {
		cmdArgs = append(cmdArgs, "--include-provenance")
		logger.Print("Include provenance: true")
	}

	if cfg.GetBool(workflow.FlagIncludeComponentMetadata) {
		cmdArgs = append(cmdArgs, "--include-component-metadata")
		logger.Print("Include component metadata: true")
	}

	if cfg.IsSet(workflow.FlagDotnetRuntimeResolution) {
		dotnetRuntimeResolution := cfg.GetBool(workflow.FlagDotnetRuntimeResolution)
		cmdArgs = append(cmdArgs, fmt.Sprintf("--dotnet-runtime-resolution=%t", dotnetRuntimeResolution))
		logger.Print("Dotnet runtime resolution: ", dotnetRuntimeResolution)
	}

	if tf := cfg.GetString(workflow.FlagDotnetTargetFramework); tf != "" {
		cmdArgs = append(cmdArgs, "--dotnet-target-framework="+tf)
		logger.Print("Dotnet target framework:", tf)
	}

	cfg.Set(configuration.RAW_CMD_ARGS, cmdArgs)
}
