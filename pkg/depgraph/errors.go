package depgraph

import (
	"errors"
	"fmt"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

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
