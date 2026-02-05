package pip

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	snyk_ecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

const (
	requirementsFile      = "requirements.txt"
	maxConcurrentInstalls = 5
	logFieldFile          = "file"
)

type Plugin struct{}

// Compile-time check to ensure Plugin implements SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// BuildDepGraphsFromDir discovers and builds dependency graphs for Python pip projects.
func (p Plugin) BuildDepGraphsFromDir(ctx context.Context, dir string, options *ecosystems.SCAPluginOptions) ([]ecosystems.SCAResult, error) {
	log := options.Global.Logger
	if log == nil {
		log = logger.Nop()
	}

	// Discover requirements.txt files
	files, err := p.discoverRequirementsFiles(ctx, dir, options)
	if err != nil {
		return nil, fmt.Errorf("failed to discover requirements files: %w", err)
	}

	if len(files) == 0 {
		log.Info(ctx, "No requirements.txt files found", logger.Attr("dir", dir))
		return []ecosystems.SCAResult{}, nil
	}

	// Get Python runtime version
	pythonVersion, err := GetPythonVersion()
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
			result, err := p.buildDepGraphFromFile(ctx, log, file, pythonVersion, options.Python.NoBuildIsolation)
			if err != nil {
				attrs := []logger.Field{
					logger.Attr(logFieldFile, file.RelPath),
					logger.Err(err),
				}

				var snykErr snyk_errors.Error
				if errors.As(err, &snykErr) && snykErr.Detail != "" {
					attrs = append(attrs, logger.Attr("detail", snykErr.Detail))
				}

				log.Error(ctx, "Failed to build dependency graph", attrs...)

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
	case options.Global.AllProjects:
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
func (p Plugin) buildDepGraphFromFile(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	pythonVersion string,
	noBuildIsolation bool,
) (ecosystems.SCAResult, error) {
	log.Debug(ctx, "Building dependency graph",
		logger.Attr(logFieldFile, file.RelPath),
		logger.Attr("python_version", pythonVersion))

	// Get pip install report (dry-run, no actual installation)
	report, err := GetInstallReport(ctx, file.Path, noBuildIsolation)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to get pip install report for %s: %w", file.RelPath, err)
	}

	// Convert report to dependency graph
	depGraph, err := report.ToDependencyGraph(ctx, log, PkgManagerPip)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to convert pip report to dependency graph for %s: %w", file.RelPath, err)
	}

	log.Debug(ctx, "Successfully built dependency graph",
		logger.Attr(logFieldFile, file.RelPath))

	return ecosystems.SCAResult{
		DepGraph: depGraph,
		Metadata: ecosystems.Metadata{
			TargetFile: file.RelPath,
			Runtime:    fmt.Sprintf("python@%s", pythonVersion),
		},
	}, nil
}

// GetPythonVersion detects the installed Python version.
func GetPythonVersion() (string, error) {
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
