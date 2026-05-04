package workflow

import (
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"
)

const WorkflowIDStr = "depgraph"

var (
	WorkflowID gafworkflow.Identifier = gafworkflow.NewWorkflowIdentifier(WorkflowIDStr)
	DataTypeID gafworkflow.Identifier = gafworkflow.NewTypeIdentifier(WorkflowID, WorkflowIDStr)
)
