package legacycli

import (
	"encoding/json"
	"errors"
	"os/exec"

	clierrors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
)

var ErrNoDepGraphsFound = errors.New("no depgraphs found")

// ExitCoder allows checking for exit codes without depending on a concrete error type.
type ExitCoder interface {
	ExitCode() int
}

// IsExitCode3 reports whether the error chain contains an error with exit code 3.
// Exit code 3 from the legacy CLI means "no projects found to test".
func IsExitCode3(err error) bool {
	var ec ExitCoder
	if errors.As(err, &ec) {
		return ec.ExitCode() == 3
	}
	return false
}

// CLIJSONError is the error type returned by the legacy cli.
type CLIJSONError struct {
	Ok       bool   `json:"ok"`
	ErrorMsg string `json:"error"`
	Path     string `json:"path"`
	exitErr  error
}

// Error returns the LegacyCliJsonError error message.
func (e *CLIJSONError) Error() string {
	return e.ErrorMsg
}

func (e *CLIJSONError) Unwrap() error {
	return e.exitErr
}

var _ interface { //nolint:errcheck // Compile-time interface assertion, no error return
	error
	Unwrap() error
} = (*CLIJSONError)(nil)

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

// tryParseErrorCatalogFromPayload returns the first ErrorCatalog error from legacy payload (JSON or JSONL). Fallback path only.
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

// tryParseFirstErrorFromJSONL returns the first ErrorCatalog error from JSONL lines (fallback path only).
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

// ExtractLegacyCLIError extracts the error message from the legacy cli if possible.
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
		var decodedError CLIJSONError
		decodedError.exitErr = input
		err := json.Unmarshal(bytes, &decodedError)
		if err == nil {
			output = &decodedError
		}
	}

	return clierrors.NewGeneralSCAFailureError(output.Error(), snyk_errors.WithCause(output))
}
