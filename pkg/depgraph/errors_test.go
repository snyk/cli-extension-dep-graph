package depgraph

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_extractLegacyCLIError_ErrorFromLegacyCLI(t *testing.T) {
	expectedMsgJSON := `{
		"ok": false,
		"error": "Hello Error",
		"path": "/"
	  }`

	inputError := &exec.ExitError{}
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte(expectedMsgJSON))

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, "Hello Error", outputError.Error())

	assert.IsType(t, &LegacyCLIJSONError{}, outputError)
}

func Test_extractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, inputError.Error(), outputError.Error())
}

func Test_extractLegacyCLIError_RetainExitError(t *testing.T) {
	inputError := &exec.ExitError{}
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.ErrorIs(t, outputError, inputError)
}
