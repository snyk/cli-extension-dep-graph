package depgraph

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
)

var (
	// WorkflowID is the unique identifier for this workflow. It should be used as
	// a reference everywhere.
	WorkflowID = workflow.WorkflowID

	// DataTypeID is the unique identifier for the data type that is being returned
	// from this workflow.
	DataTypeID = workflow.DataTypeID
)

// Init initializes the DepGraph workflow.
func Init(engine gafworkflow.Engine) error {
	flagSet := getFlagSet()

	_, err := engine.Register(
		WorkflowID,
		gafworkflow.ConfigurationOptionsFromFlagset(flagSet),
		callback)
	if err != nil {
		return fmt.Errorf("failed to register workflow: %w", err)
	}

	config_utils.AddFeatureFlagToConfig(engine, workflow.FeatureFlagUvCLI, "enableUvCLI")
	config_utils.AddFeatureFlagToConfig(engine, workflow.FeatureFlagUseUnifiedTestAPIForOSCliTest, "unified-test-api-os-cli")

	return nil
}
