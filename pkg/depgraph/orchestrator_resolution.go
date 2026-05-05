package depgraph

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/orchestrator"
)

func handleOrchestratorResolution(
	ctx gafworkflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
) ([]gafworkflow.Data, error) {
	logger.Info().Msg("Retrieving dependencies from ecosystems orchestrator")

	opts, err := ecosystems.NewPluginOptionsFromRawFlags(config.GetStringSlice(configuration.RAW_CMD_ARGS))
	if err != nil {
		return nil, fmt.Errorf("failed to parse plugin options: %w", err)
	}

	inputDir := config.GetString(configuration.INPUT_DIRECTORY)
	if inputDir == "" {
		inputDir = "."
	}

	results, err := orchestrator.ResolveDepgraphs(ctx, inputDir, *opts)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve depgraphs through ecosystems orchestrator: %w", err)
	}

	var workflowData []gafworkflow.Data
	for result := range results {
		data, mapErr := orchestratorResultToWorkflowData(&result)
		if mapErr != nil {
			return nil, mapErr
		}
		workflowData = append(workflowData, data)
	}

	if len(workflowData) > 0 {
		logger.Info().Msgf("Retrieved %d dependency graphs from ecosystems orchestrator", len(workflowData))
	}

	return workflowData, nil
}

func orchestratorResultToWorkflowData(result *ecosystems.SCAResult) (gafworkflow.Data, error) {
	if result.Error != nil {
		return nil, fmt.Errorf("failed to resolve depgraph for %s: %w",
			result.ProjectDescriptor.GetTargetFile(), result.Error)
	}

	payload, err := json.Marshal(result.DepGraph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal depgraph: %w", err)
	}

	data := gafworkflow.NewData(workflow.DataTypeID, workflow.ContentTypeJSON, payload)

	targetFile := result.ProjectDescriptor.GetTargetFile()
	data.SetMetaData(workflow.MetaKeyNormalisedTargetFile, targetFile)
	data.SetMetaData(workflow.MetaKeyTargetFileFromPlugin, targetFile)

	return data, nil
}
