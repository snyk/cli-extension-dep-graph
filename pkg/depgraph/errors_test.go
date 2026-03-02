package depgraph

import (
	"fmt"
	"os/exec"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, testDataTypeID), contentTypeJSON, []byte(expectedMsgJSON))

	outputError := ExtractLegacyCLIError(wrappedErr, []workflow.Data{data})

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

	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, testDataTypeID), contentTypeJSON, nil)

	outputError := ExtractLegacyCLIError(err, []workflow.Data{data})

	var snykErr snyk_errors.Error
	assert.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "Something bad happened", snykErr.Detail)
}

func Test_ExtractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte{})

	outputError := ExtractLegacyCLIError(inputError, []workflow.Data{data})

	var snykErr snyk_errors.Error
	assert.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, inputError.Error(), snykErr.Detail)
}

func Test_ExtractLegacyCLIError_RetainExitError(t *testing.T) {
	inputError := &exec.ExitError{}
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, "something"), "application/json", []byte{})

	outputError := ExtractLegacyCLIError(inputError, []workflow.Data{data})

	assert.ErrorIs(t, outputError, inputError)
}

func Test_ExtractLegacyCLIError_JSONLPayloadWithErrorCatalog(t *testing.T) {
	// When handleLegacyResolution calls ExtractLegacyCLIError with a JSONL payload
	// (e.g. from --print-effective-graph-with-errors), the multi-line payload is not
	// valid single JSON so the direct JSON API parse is skipped. The JSONL path
	// (tryParseFirstErrorFromJSONL) then finds the ErrorCatalog error embedded in one
	// of the JSONL lines and returns it directly, preserving the structured error.
	jsonlErrorLine := `{"error":{"jsonapi":{"version":"1.0"},"errors":[` +
		`{"id":"test-id","code":"SNYK-CLI-0001","title":"Test JSONL Error",` +
		`"detail":"error from JSONL line","meta":{"isErrorCatalogError":true,` +
		`"classification":"UNEXPECTED","level":"error"}}]},` +
		`"normalisedTargetFile":"requirements.txt"}`
	jsonlPayload := `{"depGraph":{},"normalisedTargetFile":"package-lock.json"}` +
		"\n" + jsonlErrorLine + "\n"

	inputError := fmt.Errorf("legacy cli error")
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, testDataTypeID), contentTypeJSON, []byte(jsonlPayload))

	outputError := ExtractLegacyCLIError(inputError, []workflow.Data{data})

	var snykErr snyk_errors.Error
	require.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "error from JSONL line", snykErr.Detail)
	assert.Equal(t, "Test JSONL Error", snykErr.Title)
}

func Test_ExtractLegacyCLIError_JSONAPIPayloadWithErrorCatalog(t *testing.T) {
	// When the payload is a direct JSON API error document (e.g. from --json output),
	// parseJSONAPIError extracts the ErrorCatalog error without needing the JSONL path.
	jsonAPIPayload := `{"jsonapi":{"version":"1.0"},"errors":[` +
		`{"id":"test-id","code":"SNYK-CLI-0002","title":"JSON API Error",` +
		`"detail":"error from JSON API","meta":{"isErrorCatalogError":true,` +
		`"classification":"ACTIONABLE","level":"error"}}]}`

	inputError := fmt.Errorf("legacy cli error")
	data := workflow.NewData(workflow.NewTypeIdentifier(WorkflowID, testDataTypeID), contentTypeJSON, []byte(jsonAPIPayload))

	outputError := ExtractLegacyCLIError(inputError, []workflow.Data{data})

	var snykErr snyk_errors.Error
	require.ErrorAs(t, outputError, &snykErr)
	assert.Equal(t, "error from JSON API", snykErr.Detail)
	assert.Equal(t, "JSON API Error", snykErr.Title)
}
