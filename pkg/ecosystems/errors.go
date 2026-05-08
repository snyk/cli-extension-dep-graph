package ecosystems

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// HandleFailFastResult logs the failing plugin result and returns the
// fail-fast error. Callers in other packages must NOT wrap the error, so that
// the os-flows extension can detect and render as an Error Catalog error.
//
//nolint:gocritic // hugeParam: SCAResult is small enough to copy and value semantics read more clearly here
func HandleFailFastResult(logger *zerolog.Logger, result SCAResult) error {
	targetFile := result.ProjectDescriptor.GetTargetFile()
	LogResultError(logger, targetFile, result.Error)
	return createFailFastError(targetFile, result.Error)
}

// LogResultError logs that a result for the given target file is being skipped
// due to the supplied error, including snyk_errors detail when present.
func LogResultError(logger *zerolog.Logger, targetFile string, err error) {
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) && snykErr.Detail != "" {
		logger.Printf("Skipping result for %s which errored with: %v (details: %s)", targetFile, err, snykErr.Detail)
	} else {
		logger.Printf("Skipping result for %s which errored with: %v", targetFile, err)
	}
}

// createFailFastError creates an error for fail-fast scenarios with exit code 2.
// This is used when --fail-fast is enabled and an error occurs during scanning.
func createFailFastError(lockFile string, err error) error {
	var detail string
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) && snykErr.Detail != "" {
		detail = fmt.Sprintf("Failed to scan %s: %s", lockFile, snykErr.Detail)
	} else {
		detail = fmt.Sprintf("Failed to scan %s: %s", lockFile, err.Error())
	}

	return NewExitCodeError(2, detail, err)
}

// ExitCoder describes errors carrying a process-style exit code.
// Implemented by *os/exec.ExitError and exitCodeError.
type ExitCoder interface {
	ExitCode() int
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

// NewExitCodeError creates an error carrying the supplied exit code, surfaced
// to the os-flows extension via the ExitCoder interface.
func NewExitCodeError(exitCode int, detail string, cause error) error {
	return &exitCodeError{
		err:      cause,
		exitCode: exitCode,
		detail:   detail,
	}
}
