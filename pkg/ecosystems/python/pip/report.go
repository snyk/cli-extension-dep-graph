package pip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// Report represents the minimal JSON output from pip install --report
// needed to build a dependency graph.
type Report struct {
	Install []InstallItem `json:"install"`
}

// InstallItem represents a single package in the pip install report.
type InstallItem struct {
	Metadata  PackageMetadata `json:"metadata"`
	Requested bool            `json:"requested"` // True if explicitly requested in requirements
}

// IsDirectDependency returns true if this package is a direct dependency.
func (item InstallItem) IsDirectDependency() bool {
	return item.Requested
}

// PackageMetadata contains the package name, version, and dependencies.
//
//nolint:tagliatelle // requires_dist is the field name used by pip's JSON output
type PackageMetadata struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	RequiresDist []string `json:"requires_dist"` // List of dependencies (e.g., "urllib3 (<3,>=1.21.1)")
}

// GetInstallReport runs pip install with --dry-run and --report flags to get
// a JSON report of what would be installed from a requirements file.
// No files are written to disk; the report is captured from stdout.
//
// This is a convenience wrapper around GetInstallReportWithExecutor that uses
// the default executor. For testing, use GetInstallReportWithExecutor directly.
func GetInstallReport(ctx context.Context, requirementsFile string) (*Report, error) {
	return GetInstallReportWithExecutor(ctx, requirementsFile, &DefaultExecutor{})
}

// GetInstallReportWithExecutor is a testable version that accepts a CommandExecutor.
// It runs pip install with the following flags:
//   - --dry-run: Don't actually install anything
//   - --ignore-installed: Show all packages, not just new ones
//   - --report -: Output JSON report to stdout (dash means stdout)
//   - --quiet: Suppress non-error output (except the report)
//   - -r: Read from requirements file
func GetInstallReportWithExecutor(ctx context.Context, requirementsFile string, executor CommandExecutor) (*Report, error) {
	if requirementsFile == "" {
		return nil, fmt.Errorf("requirements file path cannot be empty")
	}

	// Build pip command arguments
	args := []string{
		"install",
		"--dry-run",
		"--ignore-installed",
		"--report", "-",
		"--quiet",
		"-r", requirementsFile,
	}

	// Execute the command
	output, err := executor.Execute(ctx, "pip", args...)
	if err != nil {
		return nil, classifyPipError(err)
	}

	// Parse the JSON report
	var report Report
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse pip report: %w", err)
	}

	return &report, nil
}

// CommandExecutor is an interface for executing commands.
// This allows for dependency injection and easier testing.
type CommandExecutor interface {
	Execute(ctx context.Context, name string, args ...string) ([]byte, error)
}

// DefaultExecutor uses os/exec to run commands.
type DefaultExecutor struct{}

// Execute runs a command and returns its stdout output.
func (e *DefaultExecutor) Execute(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, &pipError{
			err:    err,
			stderr: stderr.String(),
		}
	}

	return stdout.Bytes(), nil
}

// pipError wraps an error with stderr output from pip.
type pipError struct {
	err    error
	stderr string
}

func (e *pipError) Error() string {
	return fmt.Sprintf("%v (stderr: %s)", e.err, e.stderr)
}

func (e *pipError) Unwrap() error {
	return e.err
}

// classifyPipError analyzes pip error output and returns appropriate error catalog error.
//
//nolint:gocyclo // Error classification requires checking multiple patterns sequentially
func classifyPipError(err error) error {
	var pipErr *pipError
	if !errors.As(err, &pipErr) {
		// Not a pip error, return as-is
		return fmt.Errorf("pip install failed: %w", err)
	}

	stderr := pipErr.stderr

	// Check for syntax errors in requirements.txt
	if strings.Contains(stderr, "Invalid requirement") ||
		strings.Contains(stderr, "Could not parse") ||
		strings.Contains(stderr, "invalid requirement") ||
		strings.Contains(stderr, "InvalidVersion") ||
		strings.Contains(stderr, "Invalid version") {
		return ecosystems.NewSyntaxIssuesError(
			fmt.Sprintf("Invalid syntax in requirements file: %s", stderr),
			snyk_errors.WithCause(pipErr.err),
		)
	}

	// Check for package not found errors
	if strings.Contains(stderr, "Could not find a version") ||
		strings.Contains(stderr, "No matching distribution") ||
		strings.Contains(stderr, "Could not find a version that satisfies") {
		return ecosystems.NewPythonPackageNotFoundError(
			fmt.Sprintf("Package not found: %s", stderr),
			snyk_errors.WithCause(pipErr.err),
		)
	}

	// Check for Python version mismatch
	if strings.Contains(stderr, "requires Python") ||
		strings.Contains(stderr, "Requires-Python") {
		return ecosystems.NewPipUnsupportedPythonVersionError(
			fmt.Sprintf("Python version mismatch: %s", stderr),
			snyk_errors.WithCause(pipErr.err),
		)
	}

	// Check for conflicting requirements
	if strings.Contains(stderr, "Conflict") ||
		strings.Contains(stderr, "conflicting") ||
		strings.Contains(stderr, "incompatible") {
		return ecosystems.NewPythonVersionConfictError(
			fmt.Sprintf("Conflicting package requirements: %s", stderr),
			snyk_errors.WithCause(pipErr.err),
		)
	}

	// Check for context cancellation or timeout
	if errors.Is(pipErr.err, context.Canceled) {
		// User-initiated cancellation (e.g., Ctrl+C) - not a catalog error
		return fmt.Errorf("pip install canceled: %w", pipErr.err)
	}
	if errors.Is(pipErr.err, context.DeadlineExceeded) {
		// Timeout - use catalog timeout error
		return snyk.NewTimeoutError(
			fmt.Sprintf("Pip install timed out: %s", stderr),
			snyk_errors.WithCause(pipErr.err),
		)
	}

	// Generic installation failure
	return ecosystems.NewInstallationFailureError(
		fmt.Sprintf("Pip install failed: %s", stderr),
		snyk_errors.WithCause(pipErr.err),
	)
}
