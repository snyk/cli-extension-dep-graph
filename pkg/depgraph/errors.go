package depgraph

import (
	"encoding/json"
	"errors"
	"os/exec"

	clierrors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var errNoDepGraphsFound = errors.New("no depgraphs found")

// LegacyCLIJSONError is the error type returned by the legacy cli
type LegacyCLIJSONError struct {
	Ok       bool   `json:"ok"`
	ErrorMsg string `json:"error"`
	Path     string `json:"path"`
	exitErr  error
}

// Error returns the LegacyCliJsonError error message
func (e *LegacyCLIJSONError) Error() string {
	return e.ErrorMsg
}

func (e *LegacyCLIJSONError) Unwrap() error {
	return e.exitErr
}

var _ interface {
	error
	Unwrap() error
} = new(LegacyCLIJSONError)

// extractLegacyCLIError extracts the error message from the legacy cli if possible
func extractLegacyCLIError(input error, data []workflow.Data) error {
	output := input

	// extract error from legacy cli if possible and wrap it in an error instance
	var xerr *exec.ExitError
	if errors.As(input, &xerr) && len(data) > 0 {
		bytes, _ := data[0].GetPayload().([]byte)

		var decodedError LegacyCLIJSONError
		decodedError.exitErr = input
		err := json.Unmarshal(bytes, &decodedError)
		if err == nil {
			output = &decodedError
		}
	}

	return clierrors.NewGeneralSCAFailureError(output.Error())
}
