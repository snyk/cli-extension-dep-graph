package depgraph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/internal/ptrutil"
	"github.com/snyk/cli-extension-dep-graph/internal/remoteconv"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	ecosystemslogger "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/uv"
)

func handleSBOMResolution(
	ctx gafworkflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
) ([]gafworkflow.Data, error) {
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

	converter := remoteconv.NewRemoteSBOMConverter(snykClient, ecosystemslogger.NewFromZerolog(logger))

	return handleSBOMResolutionDI(
		ctx,
		config,
		logger,
		[]ecosystems.SCAPlugin{
			uv.NewPlugin(uv.NewClient(), converter, remoteRepoURL),
			legacy.NewPlugin(ctx),
		},
	)
}

const errMsgNoSupportedProjects = "no supported projects detected"

func handleSBOMResolutionDI(
	ctx gafworkflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
	scaPlugins []ecosystems.SCAPlugin,
) ([]gafworkflow.Data, error) {
	inputDir := config.GetString(configuration.INPUT_DIRECTORY)
	if inputDir == "" {
		inputDir = "."
	}

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		logger.Printf("ERROR: failed to determine org id\n")
		return nil, snykclient.NewEmptyOrgError()
	}

	allProjects := config.GetBool(workflow.FlagAllProjects)
	failFast := config.GetBool(workflow.FlagFailFast)
	forceIncludeWorkspacePackages := config.GetBool(workflow.FlagUvWorkspacePackages)
	targetFile := config.GetString(workflow.FlagFile)
	pluginOptions := buildPluginOptions(config)

	pluginLogger := ecosystemslogger.NewFromZerolog(logger)
	workflowData := []gafworkflow.Data{}
	var problemResults []ecosystems.SCAResult
	totalResults := 0

	for _, sp := range scaPlugins {
		pluginResult, err := sp.BuildDepGraphsFromDir(
			ctx.Context(),
			pluginLogger,
			inputDir,
			pluginOptions,
		)
		if err != nil {
			return nil, fmt.Errorf("error building results: %w", err)
		}
		if pluginResult == nil {
			continue
		}

		if ffErr := checkFailFast(logger, failFast, allProjects, pluginResult.Results); ffErr != nil {
			return nil, ffErr
		}

		pluginData, pluginProblems, err := convertPluginResults(
			logger, sp, pluginResult.Results, allProjects, forceIncludeWorkspacePackages, targetFile,
		)
		if err != nil {
			return nil, err
		}

		workflowData = append(workflowData, pluginData...)
		problemResults = append(problemResults, pluginProblems...)
		totalResults += len(pluginResult.Results)

		applyProcessedFilesExclusions(config, pluginResult.ProcessedFiles)

		if !allProjects && len(pluginResult.Results) > 0 {
			break
		}
	}

	if totalResults == 0 {
		return nil, newExitCodeError(3, errMsgNoSupportedProjects, legacycli.ErrNoDepGraphsFound)
	}

	// TODO: This is a temporary implementation for rendering warnings.
	// The long-term plan is for the CLI to handle all warning rendering.
	// This will require extensions to handle `workflow.Data` objects with
	// errors and propagate them upstream rather than rendering them directly.
	// This change will require coordinated updates across extensions to
	// ensure backwards compatibility and avoid breakages.
	outputAnyWarnings(ctx, logger, problemResults, totalResults)

	return workflowData, nil
}

func buildPluginOptions(config configuration.Configuration) *ecosystems.SCAPluginOptions {
	strictOutOfSync := true
	if parsed, err := strconv.ParseBool(config.GetString(workflow.FlagStrictOutOfSync)); err == nil {
		strictOutOfSync = parsed
	}

	opts := ecosystems.NewPluginOptions().
		WithAllProjects(config.GetBool(workflow.FlagAllProjects)).
		WithForceIncludeWorkspacePackages(config.GetBool(workflow.FlagUvWorkspacePackages)).
		WithIncludeDev(config.GetBool(workflow.FlagDev)).
		WithAllowOutOfSync(!strictOutOfSync).
		WithExclude(parseExcludeFlag(config.GetString(workflow.FlagExclude))).
		WithFailFast(config.GetBool(workflow.FlagFailFast)).
		WithForceSingleGraph(config.GetBool(workflow.FlagForceSingleGraph))

	if targetFile := config.GetString(workflow.FlagFile); targetFile != "" {
		opts = opts.WithTargetFile(targetFile)
	}
	return opts
}

func checkFailFast(logger *zerolog.Logger, failFast, allProjects bool, results []ecosystems.SCAResult) error {
	if !failFast || !allProjects {
		return nil
	}
	for _, result := range results {
		if result.Error != nil {
			logResultError(logger, result.ProjectDescriptor.GetTargetFile(), result.Error)
			return createFailFastError(result.ProjectDescriptor.GetTargetFile(), result.Error)
		}
	}
	return nil
}

func convertPluginResults(
	logger *zerolog.Logger,
	plugin ecosystems.SCAPlugin,
	results []ecosystems.SCAResult,
	allProjects, forceIncludeWorkspacePackages bool,
	targetFile string,
) ([]gafworkflow.Data, []ecosystems.SCAResult, error) {
	if isMonitorJSONLBridgeInvocation(plugin, forceIncludeWorkspacePackages, targetFile) {
		return combineWorkspaceResultsAsJSONL(logger, results)
	}
	return processResultsIndividually(logger, results, allProjects)
}

func logResultError(logger *zerolog.Logger, targetFile string, err error) {
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) && snykErr.Detail != "" {
		logger.Printf("Skipping result for %s which errored with: %v (details: %s)", targetFile, err, snykErr.Detail)
	} else {
		logger.Printf("Skipping result for %s which errored with: %v", targetFile, err)
	}
}

func outputAnyWarnings(ctx gafworkflow.InvocationContext, logger *zerolog.Logger, problemResults []ecosystems.SCAResult, totalResults int) {
	if len(problemResults) > 0 {
		message := renderWarningForProblemResults(problemResults, totalResults)

		err := ctx.GetUserInterface().OutputError(fmt.Errorf("%s", message))
		if err != nil {
			logger.Printf("Failed to output warning message: %v", err)
		}
	}
}

func renderWarningForProblemResults(problemResults []ecosystems.SCAResult, totalResults int) string {
	outputMessage := ""
	for _, result := range problemResults {
		outputMessage += fmt.Sprintf("\n%s:", result.ProjectDescriptor.GetTargetFile())
		var snykErr snyk_errors.Error
		if errors.As(result.Error, &snykErr) && snykErr.Detail != "" {
			outputMessage += fmt.Sprintf("\n  %s", snykErr.Detail)
		} else {
			outputMessage += "\n  could not process manifest file"
		}
	}
	outputMessage += fmt.Sprintf("\n✗ %d/%d potential projects failed to get dependencies.", len(problemResults), totalResults)

	redStyle := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "9", Dark: "1"})
	return redStyle.Render(outputMessage)
}

// isMonitorJSONLBridgeInvocation reports whether the current plugin call is the
// `snyk monitor` TS-to-Go bridge.
//
// Background: `snyk monitor` still lives in TypeScript and invokes our Go `depgraph`
// workflow as a subprocess (see src/lib/plugins/uv/index.ts in the CLI repo). It reads
// the result from our stdout. There is a known limitation in go-application-framework
// where, if a workflow returns multiple `workflow.Data` items, only the first is
// printed to stdout and subsequent items are silently dropped — see
// https://github.com/snyk/go-application-framework/pull/559. So multiple workspace
// dep graphs cannot be returned as separate `workflow.Data` items without being lost.
//
// To work around that, when the TS uv plugin runs in `--all-projects` mode (and hence is
// expecting multiple dep-graphs back) it sets the internal `--internal-uv-workspace-packages`
// flag, and we combine our uv plugin's per-package results into a single JSONL `workflow.Data`
// (one `{depGraph, targetFile}` per line) that the TS layer then splits and parses.
//
// Once `snyk monitor` is migrated to Go this whole branch can go away. `snyk test` (already
// in Go) does not need it.
func isMonitorJSONLBridgeInvocation(plugin ecosystems.SCAPlugin, forceIncludeWorkspacePackages bool, targetFile string) bool {
	return plugin.GetName() == uv.PluginName && forceIncludeWorkspacePackages && targetFile != ""
}

// applyProcessedFilesExclusions forwards the runner-accumulated opts.Global.Exclude
// into the legacy CLI's `--exclude-paths` flag. It exists so the legacy CLI can skip
// files that have already been resolved by an earlier plugin in the same orchestration pass.
//
// This is currently a no-op: it requires snyk/cli-extension-dep-graph#152 (which adds
// the workflow.FlagExcludePaths constant + forwards it from this extension) and
// snyk/cli#6741 (which adds the --exclude-paths flag to the legacy CLI itself).
// Once both have landed, we can uncomment the below to enable the real implementation,
// and unskip any associated tests.
//
// We cannot use the existing `--exclude` flag in the meantime: it only accepts
// basenames and folder names, which would break workspace-style projects where
// multiple packages share the same manifest filename (e.g. several `package.json`
// in different workspace directories).
func applyProcessedFilesExclusions(_ configuration.Configuration, _ []string) {
	//nolint:gocritic // intentionally retained, to be used when above PRs are merged
	/*
		if len(processedFiles) == 0 {
			return
		}

		parts := make([]string, 0, len(processedFiles)+1)
		if existing := config.GetString(workflow.FlagExcludePaths); existing != "" {
			parts = append(parts, existing)
		}
		parts = append(parts, processedFiles...)
		config.Set(workflow.FlagExcludePaths, strings.Join(parts, ","))
	*/
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

func combineWorkspaceResultsAsJSONL(logger *zerolog.Logger, results []ecosystems.SCAResult) ([]gafworkflow.Data, []ecosystems.SCAResult, error) {
	if len(results) == 0 {
		return []gafworkflow.Data{}, []ecosystems.SCAResult{}, nil
	}

	var problemResults []ecosystems.SCAResult
	for _, result := range results {
		if result.Error != nil {
			logResultError(logger, result.ProjectDescriptor.GetTargetFile(), result.Error)
			problemResults = append(problemResults, result)
			return nil, problemResults, result.Error
		}
	}

	data, err := combineWorkspaceDepGraphsAsJSONL(results)
	if err != nil {
		return nil, problemResults, fmt.Errorf("failed to combine dep graphs: %w", err)
	}

	// All dep-graphs are returned as a single workflow.Data item using JSONL because
	// the CLI only returns the first workflow.Data when invoked directly (e.g. `snyk depgraph`).
	// Ideally we would return multiple workflow.Data items, but this is a workaround until
	// the CLI team addresses the underlying issue.
	// Example failing test: https://github.com/snyk/go-application-framework/pull/559
	workflowData := gafworkflow.NewData(workflow.DataTypeID, workflow.ContentTypeJSONL, data)

	targetFile := results[0].ProjectDescriptor.GetTargetFile()
	workflowData.SetMetaData(workflow.ContentLocationKey, targetFile)
	workflowData.SetMetaData(workflow.MetaKeyNormalisedTargetFile, targetFile)
	if targetFileFromPlugin := results[0].ProjectDescriptor.GetTargetFileForPlugin(); targetFileFromPlugin != nil {
		workflowData.SetMetaData(workflow.MetaKeyTargetFileFromPlugin, *targetFileFromPlugin)
	}

	return []gafworkflow.Data{workflowData}, problemResults, nil
}

func processResultsIndividually(logger *zerolog.Logger, results []ecosystems.SCAResult, allProjects bool) ([]gafworkflow.Data, []ecosystems.SCAResult, error) {
	var workflowData []gafworkflow.Data
	var problemResults []ecosystems.SCAResult
	for i := range results {
		result := &results[i]

		if result.Error != nil {
			logResultError(logger, result.ProjectDescriptor.GetTargetFile(), result.Error)
			problemResults = append(problemResults, *result)

			if !allProjects {
				return nil, problemResults, result.Error
			}

			continue
		}

		data, err := workflowDataFromDepGraph(logger, result)
		if err != nil {
			return nil, problemResults, fmt.Errorf("failed to create workflow data: %w", err)
		}
		workflowData = append(workflowData, data)
	}
	return workflowData, problemResults, nil
}

type jsonlOutputLine struct {
	DepGraph   *depgraph.DepGraph `json:"depGraph"`
	TargetFile string             `json:"targetFile"`
}

func combineWorkspaceDepGraphsAsJSONL(results []ecosystems.SCAResult) ([]byte, error) {
	var lines [][]byte
	for i := range results {
		if results[i].Error != nil {
			continue
		}
		line := jsonlOutputLine{
			DepGraph:   results[i].DepGraph,
			TargetFile: results[i].ProjectDescriptor.GetTargetFile(),
		}
		b, err := json.Marshal(line)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal depgraph: %w", err)
		}
		lines = append(lines, b)
	}
	combined := bytes.Join(lines, []byte("\n"))
	return combined, nil
}

func workflowDataFromDepGraph(logger *zerolog.Logger, result *ecosystems.SCAResult) (gafworkflow.Data, error) {
	depGraphBytes, err := json.Marshal(result.DepGraph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal depgraph data: %w", err)
	}

	data := gafworkflow.NewData(workflow.DataTypeID, workflow.ContentTypeJSON, depGraphBytes)

	targetFile := result.ProjectDescriptor.GetTargetFile()
	data.SetMetaData(workflow.ContentLocationKey, targetFile)
	data.SetMetaData(workflow.MetaKeyNormalisedTargetFile, targetFile)

	// MetaKeyTargetFileFromPlugin and MetaKeyTarget are emitted conditionally: downstream
	// CLI consumers treat presence-vs-absence as a signal when constructing API payloads
	// (registry uses both for project identification). The legacy plugin populates these
	// per the upstream legacy CLI's behavior; other plugins typically leave them nil.
	targetFileFromPlugin := result.ProjectDescriptor.GetTargetFileForPlugin()
	if targetFileFromPlugin != nil {
		data.SetMetaData(workflow.MetaKeyTargetFileFromPlugin, *targetFileFromPlugin)
	}

	var target string
	if result.ProjectDescriptor.Identity.Legacy != nil {
		target = string(result.ProjectDescriptor.Identity.Legacy.Target)
	}
	if target != "" {
		data.SetMetaData(workflow.MetaKeyTarget, target)
	}

	var pluginName string
	if result.ResolverMetadata != nil {
		pluginName = result.ResolverMetadata.PluginName
	}

	logger.Debug().
		Str("plugin", pluginName).
		Str("targetFile", targetFile).
		Str("targetFileFromPlugin", ptrutil.DerefOr(targetFileFromPlugin, "")).
		Str("target", target).
		Msg("emitting workflow.Data")

	return data, nil
}
