package depgraph

import (
	"bytes"
	"log"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var (
	jsonSeparatorEnd    = []byte("DepGraph end")
	jsonSeparatorData   = []byte("DepGraph data:")
	jsonSeparatorTarget = []byte("DepGraph target:")

	legacyWorkflowID = workflow.NewWorkflowIdentifier("legacycli")
)

func callback(ctx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	depGraphList := []workflow.Data{}

	engine := ctx.GetEngine()
	config := ctx.GetConfiguration()
	logger := ctx.GetLogger()

	logger.Println("DepGraph workflow start")

	// prepare invocation of the legacy cli
	prepareLegacyFlags(config, logger)

	legacyData, legacyCLIError := engine.InvokeWithConfig(legacyWorkflowID, config)
	if legacyCLIError != nil {
		return depGraphList, extractLegacyCLIError(legacyCLIError, legacyData)
	}

	snykOutput, _ := legacyData[0].GetPayload().([]byte)

	if len(snykOutput) <= 0 {
		return depGraphList, errNoDepGraphsFound
	}

	// split up dependency data from legacy cli
	separatedJSONRawData := bytes.Split(snykOutput, jsonSeparatorEnd)
	for i := range separatedJSONRawData {
		rawData := separatedJSONRawData[i]
		if bytes.Contains(rawData, jsonSeparatorData) {
			graphStartIndex := bytes.Index(rawData, jsonSeparatorData) + len(jsonSeparatorData)
			graphEndIndex := bytes.Index(rawData, jsonSeparatorTarget)
			targetNameStartIndex := graphEndIndex + len(jsonSeparatorTarget)
			targetNameEndIndex := len(rawData) - 1

			targetName := rawData[targetNameStartIndex:targetNameEndIndex]
			depGraphJSON := rawData[graphStartIndex:graphEndIndex]

			data := workflow.NewData(DataTypeID, "application/json", depGraphJSON)
			data.SetMetaData("Content-Location", strings.TrimSpace(string(targetName)))
			depGraphList = append(depGraphList, data)
		}
	}

	logger.Printf("depgraph workflow done (%d)", len(depGraphList))

	return depGraphList, nil
}

func prepareLegacyFlags(cfg configuration.Configuration, logger *log.Logger) { //nolint:gocyclo
	cmdArgs := []string{"test", "--print-graph", "--json"}

	if allProjects := cfg.GetBool("all-projects"); allProjects {
		cmdArgs = append(cmdArgs, "--all-projects")
	}

	if cfg.GetBool("fail-fast") {
		cmdArgs = append(cmdArgs, "--fail-fast")
	}

	if exclude := cfg.GetString("exclude"); exclude != "" {
		cmdArgs = append(cmdArgs, "--exclude="+exclude)
		logger.Println("Exclude:", exclude)
	}

	if detectionDepth := cfg.GetString("detection-depth"); detectionDepth != "" {
		cmdArgs = append(cmdArgs, "--detection-depth="+detectionDepth)
		logger.Println("Detection depth:", detectionDepth)
	}

	if targetDir := cfg.GetString(configuration.INPUT_DIRECTORY); targetDir != "" {
		cmdArgs = append(cmdArgs, targetDir)
		logger.Println("Target directory:", targetDir)
	}

	if file := cfg.GetString("file"); file != "" {
		cmdArgs = append(cmdArgs, "--file="+file)
		logger.Println("File:", file)
	}

	if cfg.GetBool("unmanaged") {
		cmdArgs = append(cmdArgs, "--unmanaged")
		logger.Println("Is unmanaged: true")
	}

	if cfg.GetBool(configuration.DEBUG) {
		cmdArgs = append(cmdArgs, "--debug")
		logger.Println("Debug: true")
	}

	if cfg.GetBool("dev") {
		cmdArgs = append(cmdArgs, "--dev")
		logger.Println("Dev dependencies: true")
	}

	if cfg.GetBool("prune-repeated-subdependencies") {
		cmdArgs = append(cmdArgs, "--prune-repeated-subdependencies")
		logger.Println("Prune repeated sub-dependencies: true")
	}

	if cfg.GetBool("maven-aggregate-project") {
		cmdArgs = append(cmdArgs, "--maven-aggregate-project")
		logger.Println("Ensure all modules are resolvable by the Maven reactor: true")
	}

	if cfg.GetBool("scan-unmanaged") {
		cmdArgs = append(cmdArgs, "--scan-unmanaged")
		logger.Println("Specify an individual JAR, WAR, or AAR file: true")
	}

	if cfg.GetBool("scan-all-unmanaged") {
		cmdArgs = append(cmdArgs, "--scan-all-unmanaged")
		logger.Println("Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder: true")
	}

	cfg.Set(configuration.RAW_CMD_ARGS, cmdArgs)
}
