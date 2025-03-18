package depgraph

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func Test_extractLegacyCLIError_ErrorFromLegacyCLI(t *testing.T) {
	expectedMsgJSON := `{
		"ok": false,
		"error": "Hello Error",
		"path": "/"
	  }`

	wrappedErr := fmt.Errorf("something bad happened: %w", &exec.ExitError{})
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte(expectedMsgJSON))

	outputError := extractLegacyCLIError(wrappedErr, []workflow.Data{data})

	var snykErr snyk_errors.Error
	assert.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "Hello Error", snykErr.Detail)
}

func Test_extractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	var snykErr snyk_errors.Error
	assert.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, inputError.Error(), snykErr.Detail)
}

func Test_extractLegacyCLIError_RetainExitError(t *testing.T) {
	inputError := &exec.ExitError{}
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.ErrorIs(t, outputError, inputError)
}
