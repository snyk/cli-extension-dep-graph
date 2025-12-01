package pip

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	snyk_ecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
)

const (
	requirementsFile      = "requirements.txt"
	maxConcurrentInstalls = 5
	logFieldFile          = "file"
)

type Plugin struct {
	// Executor is an optional CommandExecutor for running pip commands.
	// If nil, DefaultExecutor is used.
	Executor CommandExecutor
}

// Compile-time check to ensure Plugin implements SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// BuildDepGraphsFromDir discovers and builds dependency graphs for Python pip projects.
func (p Plugin) BuildDepGraphsFromDir(ctx context.Context, dir string, options *ecosystems.SCAPluginOptions) ([]ecosystems.SCAResult, error) {
	// Discover requirements.txt files
	files, err := p.discoverRequirementsFiles(ctx, dir, options)
	if err != nil {
		return nil, fmt.Errorf("failed to discover requirements files: %w", err)
	}

	if len(files) == 0 {
		slog.Info("No requirements.txt files found", slog.String("dir", dir))
		return []ecosystems.SCAResult{}, nil
	}

	// Get Python runtime version
	pythonVersion, err := getPythonVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to detect Python version: %w", err)
	}

	// Build dependency graphs concurrently for each requirements file
	// Limit concurrency to avoid overwhelming the system
	var mu sync.Mutex
	results := make([]ecosystems.SCAResult, 0, len(files))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentInstalls)

	for _, file := range files {
		g.Go(func() error {
			result, err := p.buildDepGraphFromFile(ctx, file, pythonVersion)
			if err != nil {
				slog.Error("Failed to build dependency graph",
					slog.String(logFieldFile, file.RelPath),
					slog.Any("error", err))
				result = ecosystems.SCAResult{
					Metadata: ecosystems.Metadata{
						TargetFile: file.RelPath,
						Runtime:    fmt.Sprintf("python@%s", pythonVersion),
					},
					Error: err,
				}
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("error building dependency graphs: %w", err)
	}

	return results, nil
}

// discoverRequirementsFiles finds requirements.txt files based on the provided options.
func (p Plugin) discoverRequirementsFiles(ctx context.Context, dir string, options *ecosystems.SCAPluginOptions) ([]discovery.FindResult, error) {
	var findOpts []discovery.FindOption

	switch {
	case options.Global.TargetFile != nil:
		// Use specific target file if provided
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(*options.Global.TargetFile),
		}
	case options.Global.AllSubProjects:
		// Find all requirements.txt files recursively
		// Exclude common directories to avoid scanning unnecessary paths
		findOpts = []discovery.FindOption{
			discovery.WithInclude(requirementsFile),
			discovery.WithExcludes(".*", "__pycache__", "*.egg-info", "dist", "build", "venv"),
		}
	default:
		// Default: find requirements.txt at root only
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(requirementsFile),
		}
	}

	files, err := discovery.FindFiles(ctx, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to find files: %w", err)
	}
	return files, nil
}

// buildDepGraphFromFile builds a dependency graph from a requirements.txt file.
func (p Plugin) buildDepGraphFromFile(ctx context.Context, file discovery.FindResult, pythonVersion string) (ecosystems.SCAResult, error) {
	slog.Debug("Building dependency graph",
		slog.String(logFieldFile, file.RelPath),
		slog.String("python_version", pythonVersion))

	// Get pip install report (dry-run, no actual installation)
	executor := p.Executor
	if executor == nil {
		executor = &DefaultExecutor{}
	}
	report, err := GetInstallReportWithExecutor(ctx, file.Path, executor)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to get pip install report for %s: %w", file.RelPath, err)
	}

	// Convert report to dependency graph
	depGraph, err := report.ToDependencyGraph()
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to convert pip report to dependency graph for %s: %w", file.RelPath, err)
	}

	slog.Debug("Successfully built dependency graph",
		slog.String(logFieldFile, file.RelPath),
		slog.Int("packages", len(depGraph.Packages)))

	return ecosystems.SCAResult{
		DepGraph: depGraph,
		Metadata: ecosystems.Metadata{
			TargetFile: file.RelPath,
			Runtime:    fmt.Sprintf("python@%s", pythonVersion),
		},
	}, nil
}

// getPythonVersion detects the installed Python version.
func getPythonVersion() (string, error) {
	// Try python3 first (more common on Unix systems)
	if version, err := execPythonVersion("python3"); err == nil {
		return version, nil
	}

	// Fall back to python (Windows or systems with python pointing to Python 3)
	if version, err := execPythonVersion("python"); err == nil {
		return version, nil
	}

	// Python not found in PATH
	return "", snyk_ecosystems.NewInstallationFailureError(
		"Python is not installed or not found in PATH. Please install Python 3 and ensure it is available in your system PATH.",
	)
}

// execPythonVersion executes python --version and parses the output.
func execPythonVersion(pythonCmd string) (string, error) {
	cmd := exec.Command(pythonCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute %s --version: %w", pythonCmd, err)
	}

	// Parse "Python 3.11.5" -> "3.11.5"
	versionStr := strings.TrimSpace(string(output))
	versionStr = strings.TrimPrefix(versionStr, "Python ")

	return versionStr, nil
}
