package legacycli

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
)

const (
	testDataTypeID = "something"
)

func Test_ExtractLegacyCLIError_ErrorFromLegacyCLI(t *testing.T) {
	expectedMsgJSON := `{
		"ok": false,
		"error": "Hello Error",
		"path": "/"
	  }`

	wrappedErr := fmt.Errorf("something bad happened: %w", &exec.ExitError{})
	data := gafworkflow.NewData(gafworkflow.NewTypeIdentifier(workflow.WorkflowID, testDataTypeID), workflow.ContentTypeJSON, []byte(expectedMsgJSON))

	outputError := ExtractLegacyCLIError(wrappedErr, []gafworkflow.Data{data})

	var snykErr snyk_errors.Error
	assert.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "Hello Error", snykErr.Detail)
}

func Test_ExtractLegacyCLIError_ErrorCatalogFromLegacyCLI(t *testing.T) {
	err := snyk_errors.Error{
		ID:     "SNYK-ID-FOO-BAR-123",
		Title:  "Some error",
		Detail: "Something bad happened",
	}

	data := gafworkflow.NewData(gafworkflow.NewTypeIdentifier(workflow.WorkflowID, testDataTypeID), workflow.ContentTypeJSON, nil)

	outputError := ExtractLegacyCLIError(err, []gafworkflow.Data{data})

	var snykErr snyk_errors.Error
	assert.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "Something bad happened", snykErr.Detail)
}

func Test_ExtractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := gafworkflow.NewData(gafworkflow.NewTypeIdentifier(workflow.WorkflowID, "something"), "application/json", []byte{})

	outputError := ExtractLegacyCLIError(inputError, []gafworkflow.Data{data})

	var snykErr snyk_errors.Error
	assert.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, inputError.Error(), snykErr.Detail)
}

func Test_ExtractLegacyCLIError_RetainExitError(t *testing.T) {
	inputError := &exec.ExitError{}
	data := gafworkflow.NewData(gafworkflow.NewTypeIdentifier(workflow.WorkflowID, "something"), "application/json", []byte{})

	outputError := ExtractLegacyCLIError(inputError, []gafworkflow.Data{data})

	assert.ErrorIs(t, outputError, inputError)
}

func Test_ExtractLegacyCLIError_JSONLPayloadWithErrorCatalog(t *testing.T) {
	jsonlErrorLine := `{"error":{"jsonapi":{"version":"1.0"},"errors":[` +
		`{"id":"test-id","code":"SNYK-CLI-0001","title":"Test JSONL Error",` +
		`"detail":"error from JSONL line","meta":{"isErrorCatalogError":true,` +
		`"classification":"UNEXPECTED","level":"error"}}]},` +
		`"normalisedTargetFile":"requirements.txt"}`
	jsonlPayload := `{"depGraph":{},"normalisedTargetFile":"package-lock.json"}` +
		"\n" + jsonlErrorLine + "\n"

	inputError := fmt.Errorf("legacy cli error")
	data := gafworkflow.NewData(gafworkflow.NewTypeIdentifier(workflow.WorkflowID, testDataTypeID), workflow.ContentTypeJSON, []byte(jsonlPayload))

	outputError := ExtractLegacyCLIError(inputError, []gafworkflow.Data{data})

	var snykErr snyk_errors.Error
	require.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "error from JSONL line", snykErr.Detail)
	assert.Equal(t, "Test JSONL Error", snykErr.Title)
}

func Test_ExtractLegacyCLIError_JSONAPIPayloadWithErrorCatalog(t *testing.T) {
	jsonAPIPayload := `{"jsonapi":{"version":"1.0"},"errors":[` +
		`{"id":"test-id","code":"SNYK-CLI-0002","title":"JSON API Error",` +
		`"detail":"error from JSON API","meta":{"isErrorCatalogError":true,` +
		`"classification":"ACTIONABLE","level":"error"}}]}`

	inputError := fmt.Errorf("legacy cli error")
	data := gafworkflow.NewData(gafworkflow.NewTypeIdentifier(workflow.WorkflowID, testDataTypeID), workflow.ContentTypeJSON, []byte(jsonAPIPayload))

	outputError := ExtractLegacyCLIError(inputError, []gafworkflow.Data{data})

	var snykErr snyk_errors.Error
	require.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "error from JSON API", snykErr.Detail)
	assert.Equal(t, "JSON API Error", snykErr.Title)
}
