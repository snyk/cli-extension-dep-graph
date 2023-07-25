package depgraph

import "github.com/snyk/go-application-framework/pkg/workflow"

var (
	// WorkflowID is the unique identifier for this workflow. It should be used as
	// a reference everywhere.
	WorkflowID workflow.Identifier = workflow.NewWorkflowIdentifier("depgraph")

	// DataTypeID is the unique identifier for the data type that is being returned
	// from this workflow.
	DataTypeID workflow.Identifier = workflow.NewTypeIdentifier(WorkflowID, "depgraph")
)

// Init initializes the DepGraph workflow.
func Init(engine workflow.Engine) error {
	flags := getFlagSet()

	_, err := engine.Register(
		WorkflowID,
		workflow.ConfigurationOptionsFromFlagset(flags),
		callback)

	return err
}
