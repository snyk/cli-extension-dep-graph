package pipenv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sync/errgroup"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/prchecks"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
)

const (
	pipfileFile           = "Pipfile"
	pipfileLockFile       = "Pipfile.lock"
	maxConcurrentInstalls = 5
	logFieldFile          = "file"
	pythonRuntimeFmt      = "python@%s"
)

type Plugin struct{}

// Compile-time check to ensure Plugin implements SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// BuildDepGraphsFromDir discovers and builds dependency graphs for Pipenv projects.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	if log == nil {
		log = logger.Nop()
	}

	// Discover Pipfile files
	files, err := p.discoverPipfiles(ctx, dir, options)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Pipfiles: %w", err)
	}

	if len(files) == 0 {
		log.Info(ctx, "No Pipfile files found", logger.Attr("dir", dir))
		return &ecosystems.PluginResult{}, nil
	}

	// Get Python runtime version
	pythonVersion, err := pip.GetPythonVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to detect Python version: %w", err)
	}

	// Build dependency graphs concurrently for each Pipfile
	var mu sync.Mutex
	results := make([]ecosystems.SCAResult, 0, len(files))

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentInstalls)

	for _, file := range files {
		g.Go(func() error {
			result, err := p.buildDepGraphFromPipfile(ctx, log, file, pythonVersion, options.Python.NoBuildIsolation, options.Global.IncludeDev)
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
						Runtime:    fmt.Sprintf(pythonRuntimeFmt, pythonVersion),
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

	processedFiles := make([]string, 0, len(results))
	for _, result := range results {
		processedFiles = append(processedFiles, result.Metadata.TargetFile)
	}

	return &ecosystems.PluginResult{
		Results:        results,
		ProcessedFiles: processedFiles,
	}, nil
}

// discoverPipfiles finds Pipfile files based on the provided options.
func (p Plugin) discoverPipfiles(ctx context.Context, dir string, options *ecosystems.SCAPluginOptions) ([]discovery.FindResult, error) {
	var findOpts []discovery.FindOption

	switch {
	case options.Global.TargetFile != nil:
		// Use specific target file if provided
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(*options.Global.TargetFile),
		}
	case options.Global.AllProjects:
		// Find all Pipfile files recursively
		findOpts = []discovery.FindOption{
			discovery.WithInclude(pipfileFile),
			discovery.WithExcludes(".*", "__pycache__", "*.egg-info", "dist", "build", "venv"),
		}
	default:
		// Default: find Pipfile at root only
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(pipfileFile),
		}
	}

	files, err := discovery.FindFiles(ctx, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to find files: %w", err)
	}
	return files, nil
}

// buildDepGraphFromPipfile builds a dependency graph from a Pipfile and its lock file.
func (p Plugin) buildDepGraphFromPipfile(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	pythonVersion string,
	noBuildIsolation bool,
	includeDevDeps bool,
) (ecosystems.SCAResult, error) {
	log.Debug(ctx, "Building dependency graph from Pipfile",
		logger.Attr(logFieldFile, file.RelPath),
		logger.Attr("python_version", pythonVersion))

	// Parse Pipfile
	pipfile, err := ParsePipfile(file.Path)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to parse Pipfile: %w", err)
	}

	// Check for Pipfile.lock in the same directory
	pipfileDir := filepath.Dir(file.Path)
	lockfilePath := filepath.Join(pipfileDir, pipfileLockFile)

	var lockfile *PipfileLock
	if _, statErr := os.Stat(lockfilePath); statErr == nil {
		lockfile, err = ParsePipfileLock(lockfilePath)
		if err != nil {
			return ecosystems.SCAResult{}, snykecosystems.NewUnparseableLockFileError(
				fmt.Sprintf("Failed to parse Pipfile.lock: %v", err),
				snyk_errors.WithCause(err),
			)
		}
	} else if os.IsNotExist(statErr) {
		return ecosystems.SCAResult{}, prchecks.NewManifestNotFoundError(
			fmt.Sprintf("Pipfile.lock not found at %s. Run 'pipenv lock' to generate it.", lockfilePath))
	} else {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to check for Pipfile.lock: %w", statErr)
	}

	// Get pip install report with packages and constraints passed directly
	report, err := p.getInstallReport(ctx, pipfile, lockfile, noBuildIsolation, includeDevDeps)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to get pip install report: %w", err)
	}

	// Convert report to dependency graph
	depGraph, err := report.ToDependencyGraph(ctx, log, pip.PkgManagerPipenv)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to convert pip report to dependency graph: %w", err)
	}

	log.Info(ctx, "Successfully built dependency graph from Pipfile",
		logger.Attr(logFieldFile, file.RelPath))

	return ecosystems.SCAResult{
		DepGraph: depGraph,
		Metadata: ecosystems.Metadata{
			TargetFile: file.RelPath,
			Runtime:    fmt.Sprintf(pythonRuntimeFmt, pythonVersion),
		},
	}, nil
}

// getInstallReport runs pip install --dry-run with packages and constraints passed directly.
// The lockfile is always present (either parsed or generated), so we pass only package names
// and let the constraints file (from lockfile) control all version pinning. This avoids
// conflicts where pip sees the same package specified twice with different version constraints.
func (p Plugin) getInstallReport(
	ctx context.Context,
	pipfile *Pipfile,
	lockfile *PipfileLock,
	noBuildIsolation bool,
	includeDevDeps bool,
) (*pip.Report, error) {
	// Get package names without version specifiers
	packages := pipfile.ToPackageNames(includeDevDeps)
	if len(packages) == 0 {
		// Return empty report for empty Pipfile (creates depgraph with just root node)
		return &pip.Report{}, nil
	}

	// Get constraints from lockfile (all packages with pinned versions)
	constraints := lockfile.ToConstraints(includeDevDeps)

	// Get pip install report passing packages and constraints directly
	report, err := pip.GetInstallReportFromPackages(ctx, packages, constraints, noBuildIsolation)
	if err != nil {
		return nil, fmt.Errorf("pip install report failed: %w", err)
	}
	return report, nil
}
