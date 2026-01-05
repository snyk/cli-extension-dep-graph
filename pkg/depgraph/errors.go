package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	clierrors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var errNoDepGraphsFound = errors.New("no depgraphs found")

// LegacyCLIJSONError is the error type returned by the legacy cli.
type LegacyCLIJSONError struct {
	Ok       bool   `json:"ok"`
	ErrorMsg string `json:"error"`
	Path     string `json:"path"`
	exitErr  error
}

// Error returns the LegacyCliJsonError error message.
func (e *LegacyCLIJSONError) Error() string {
	return e.ErrorMsg
}

func (e *LegacyCLIJSONError) Unwrap() error {
	return e.exitErr
}

var _ interface { //nolint:errcheck // Compile-time interface assertion, no error return
	error
	Unwrap() error
} = (*LegacyCLIJSONError)(nil)

// extractLegacyCLIError extracts the error message from the legacy cli if possible.
func extractLegacyCLIError(input error, data []workflow.Data) error {
	output := input

	var errCatalogErr snyk_errors.Error
	if errors.As(input, &errCatalogErr) {
		return input
	}

	// extract error from legacy cli if possible and wrap it in an error instance
	var xerr *exec.ExitError
	if errors.As(input, &xerr) && len(data) > 0 {
		bytes, ok := data[0].GetPayload().([]byte)
		if !ok {
			return clierrors.NewGeneralSCAFailureError(output.Error(), snyk_errors.WithCause(output))
		}
		var decodedError LegacyCLIJSONError
		decodedError.exitErr = input
		err := json.Unmarshal(bytes, &decodedError)
		if err == nil {
			output = &decodedError
		}
	}

	return clierrors.NewGeneralSCAFailureError(output.Error(), snyk_errors.WithCause(output))
}

// exitCoder interface allows checking for exit codes without depending on concrete exec.ExitError.
type exitCoder interface {
	ExitCode() int
}

// isExitCode3 checks if the error chain contains an error with exit code 3.
// Exit code 3 typically means "no projects found to test" in the legacy CLI.
func isExitCode3(err error) bool {
	var ec exitCoder
	if errors.As(err, &ec) {
		return ec.ExitCode() == 3
	}
	return false
}

// exitCodeError wraps an error with a specific exit code.
type exitCodeError struct {
	err      error
	exitCode int
	detail   string
}

func (e *exitCodeError) Error() string {
	return e.detail
}

func (e *exitCodeError) Unwrap() error {
	return e.err
}

func (e *exitCodeError) ExitCode() int {
	return e.exitCode
}

// newExitCodeError creates an error with a specific exit code.
func newExitCodeError(exitCode int, detail string, cause error) error {
	return &exitCodeError{
		err:      cause,
		exitCode: exitCode,
		detail:   detail,
	}
}

// createFailFastError creates an error for fail-fast scenarios with exit code 2.
// This is used when --fail-fast is enabled and an error occurs during scanning.
func createFailFastError(lockFile string, err error) error {
	var detail string
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		detail = fmt.Sprintf("Failed to scan %s: %s", lockFile, snykErr.Detail)
	} else {
		detail = fmt.Sprintf("Failed to scan %s: %s", lockFile, err.Error())
	}

	return newExitCodeError(2, detail, err)
}
