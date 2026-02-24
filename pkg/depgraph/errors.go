package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"

	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
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

type jsonAPIErrorWrapper struct {
	Error json.RawMessage `json:"error"`
}

// parseJSONAPIError returns the first error from the JSON API "errors" array if present.
// The legacy CLI uses JSON API format where "error" contains "errors": [].
func parseJSONAPIError(bytes []byte) (snyk_errors.Error, bool) {
	errs, err := snyk_errors.FromJSONAPIErrorBytes(bytes)
	if err != nil || len(errs) == 0 {
		return snyk_errors.Error{}, false
	}
	return errs[0], true
}

// tryParseErrorCatalogFromPayload extracts a single ErrorCatalog error from legacy workflow
// data when the invocation fails. Used only in the fallback path where we return one error
// (e.g. no parseable JSONL to build partial results). The payload may be single JSON or
// JSONL; we return the first parseable error so os-flows can render it. The main path
// (orchestrator) parses JSONL and returns full results (one SCAResult per line) instead.
func tryParseErrorCatalogFromPayload(data []workflow.Data) (snyk_errors.Error, bool) {
	if len(data) == 0 {
		return snyk_errors.Error{}, false
	}
	bytes, ok := data[0].GetPayload().([]byte)
	if !ok || len(bytes) == 0 {
		return snyk_errors.Error{}, false
	}
	// Try single JSON (e.g. legacy --json output).
	if err, ok := parseJSONAPIError(bytes); ok {
		return err, true
	}
	var wrapper jsonAPIErrorWrapper
	if json.Unmarshal(bytes, &wrapper) == nil && len(wrapper.Error) > 0 {
		if err, ok := parseJSONAPIError(wrapper.Error); ok {
			return err, true
		}
	}
	// Payload may be JSONL (e.g. --print-effective-graph-with-errors): one line per project,
	// each line may have an "error" field with "errors": [].
	if err, ok := tryParseFirstErrorFromJSONL(bytes); ok {
		return err, true
	}
	return snyk_errors.Error{}, false
}

// tryParseFirstErrorFromJSONL parses payload as JSONL and returns the first parseable
// ErrorCatalog error (used only when we need a single error for the fallback path, not
// when building full partial results in the orchestrator).
func tryParseFirstErrorFromJSONL(payload []byte) (snyk_errors.Error, bool) {
	outputs, err := parsers.NewJSONL().ParseOutput(payload)
	if err != nil || len(outputs) == 0 {
		return snyk_errors.Error{}, false
	}
	for i := range outputs {
		if len(outputs[i].Error) == 0 {
			continue
		}
		if err, ok := parseJSONAPIError(outputs[i].Error); ok {
			return err, true
		}
	}
	return snyk_errors.Error{}, false
}

// extractLegacyCLIError extracts the error message from the legacy cli if possible.
func ExtractLegacyCLIError(input error, data []workflow.Data) error {
	var errCatalogErr snyk_errors.Error
	if errors.As(input, &errCatalogErr) {
		return input
	}
	if err, ok := tryParseErrorCatalogFromPayload(data); ok {
		return err
	}

	output := input

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
