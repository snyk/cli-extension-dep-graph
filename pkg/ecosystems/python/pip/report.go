package pip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	Metadata        PackageMetadata `json:"metadata"`
	Requested       bool            `json:"requested"`        // True if explicitly requested in requirements
	RequestedExtras []string        `json:"requested_extras"` //nolint:tagliatelle // pip's JSON output uses snake_case
}

// IsDirectDependency returns true if this package is a direct dependency.
func (item *InstallItem) IsDirectDependency() bool {
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

func (p *PackageMetadata) GetNormalizePackageName() string {
	normalized := strings.ToLower(p.Name)
	normalized = strings.ReplaceAll(normalized, "_", "-")
	return normalized
}

func (p *PackageMetadata) GetNormalizeVersion() string {
	if p.Version == "" {
		return "?"
	}
	return p.Version
}

// GetInstallReport runs pip install with --dry-run and --report flags to get
// a JSON report of what would be installed from a requirements file.
func GetInstallReport(ctx context.Context, requirementsFile string, noBuildIsolation bool) (*Report, error) {
	return GetInstallReportWithExecutor(ctx, requirementsFile, noBuildIsolation, &DefaultExecutor{})
}

// GetInstallReportWithExecutor is a testable version that accepts a CommandExecutor.
func GetInstallReportWithExecutor(ctx context.Context, requirementsFile string, noBuildIsolation bool, executor CommandExecutor) (*Report, error) {
	if requirementsFile == "" {
		return nil, fmt.Errorf("requirements file path cannot be empty")
	}
	return runPipInstall(ctx, []string{"-r", requirementsFile}, nil, noBuildIsolation, executor)
}

// GetInstallReportFromPackages runs pip install with --dry-run and --report flags,
// passing packages directly as command arguments instead of using a requirements file.
// Constraints are passed via stdin using /dev/stdin as the constraint file path.
func GetInstallReportFromPackages(ctx context.Context, packages, constraints []string, noBuildIsolation bool) (*Report, error) {
	return GetInstallReportFromPackagesWithExecutor(ctx, packages, constraints, noBuildIsolation, &DefaultExecutor{})
}

// GetInstallReportFromPackagesWithExecutor is a testable version that accepts a CommandExecutor.
func GetInstallReportFromPackagesWithExecutor(
	ctx context.Context,
	packages, constraints []string,
	noBuildIsolation bool,
	executor CommandExecutor,
) (*Report, error) {
	if len(packages) == 0 {
		return nil, fmt.Errorf("packages list cannot be empty")
	}
	return runPipInstall(ctx, packages, constraints, noBuildIsolation, executor)
}

// runPipInstall executes pip install --dry-run and returns the parsed report.
// It runs pip install with the following flags:
//   - --dry-run: Don't actually install anything
//   - --ignore-installed: Show all packages, not just new ones
//   - --report -: Output JSON report to stdout (dash means stdout)
//   - --quiet: Suppress non-error output (except the report)
//   - --no-build-isolation: Disable build isolation when noBuildIsolation is true
//   - --index-url: Custom PyPI index (if PIP_TEST_INDEX_URL is set)
func runPipInstall(ctx context.Context, packageArgs, constraints []string, noBuildIsolation bool, executor CommandExecutor) (*Report, error) {
	args := []string{
		"install",
		"--dry-run",
		"--ignore-installed",
		"--report", "-",
		"--quiet",
	}

	args = append(args, packageArgs...)

	// Add constraints via /dev/stdin if we have any
	var stdinData string
	if len(constraints) > 0 {
		args = append(args, "-c", "/dev/stdin")
		stdinData = strings.Join(constraints, "\n")
	}

	if noBuildIsolation {
		args = append(args, "--no-build-isolation")
	}

	// Add custom index URL from environment variable (for testing with devpi/custom index)
	if indexURL := os.Getenv("PIP_TEST_INDEX_URL"); indexURL != "" {
		args = append(args, "--index-url", indexURL)
	}

	output, err := executor.Execute(ctx, stdinData, "pip", args...)
	if err != nil {
		return nil, classifyPipError(ctx, err)
	}

	var report Report
	if err := json.Unmarshal(output, &report); err != nil {
		return nil, fmt.Errorf("failed to parse pip report: %w", err)
	}

	return &report, nil
}

// CommandExecutor is an interface for executing commands.
// This allows for dependency injection and easier testing.
type CommandExecutor interface {
	Execute(ctx context.Context, stdin, name string, args ...string) ([]byte, error)
}

// DefaultExecutor uses os/exec to run commands.
type DefaultExecutor struct{}

// Execute runs a command with optional stdin input and returns its stdout output.
func (e *DefaultExecutor) Execute(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

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
func classifyPipError(ctx context.Context, err error) error {
	// Check for context cancellation or timeout early
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled) {
		// User-initiated cancellation (e.g., Ctrl+C) - not a catalog error
		return fmt.Errorf("pip install canceled: %w", ctx.Err())
	}

	var pipErr *pipError
	if !errors.As(err, &pipErr) {
		// Not a pip error, return as-is
		return fmt.Errorf("pip install failed: %w", err)
	}

	if errors.Is(pipErr.err, context.DeadlineExceeded) {
		// Timeout - use catalog timeout error
		return snyk.NewTimeoutError(
			"Pip install timed out",
			snyk_errors.WithCause(pipErr.err),
		)
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

	// Generic installation failure
	return ecosystems.NewInstallationFailureError(
		fmt.Sprintf("Pip install failed: %s", stderr),
		snyk_errors.WithCause(pipErr.err),
	)
}
