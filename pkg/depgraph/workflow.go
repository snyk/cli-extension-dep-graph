package depgraph

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/constants"
)

const (
	workflowIDStr = "depgraph"
)

var (
	// WorkflowID is the unique identifier for this workflow. It should be used as
	// a reference everywhere.
	WorkflowID workflow.Identifier = workflow.NewWorkflowIdentifier(workflowIDStr)

	// DataTypeID is the unique identifier for the data type that is being returned
	// from this workflow.
	DataTypeID workflow.Identifier = workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
)

// Init initializes the DepGraph workflow.
func Init(engine workflow.Engine) error {
	flags := getFlagSet()

	_, err := engine.Register(
		WorkflowID,
		workflow.ConfigurationOptionsFromFlagset(flags),
		callback)
	if err != nil {
		return fmt.Errorf("failed to register workflow: %w", err)
	}

	// SBOM support FF.
	config_utils.AddFeatureFlagsToConfig(engine, map[string]string{
		constants.FeatureFlagShowMavenBuildScope: constants.ShowMavenBuildScope,
		constants.FeatureFlagShowNpmScope:        constants.ShowNpmScope,
	})

	return nil
}
