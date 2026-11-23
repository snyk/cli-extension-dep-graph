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

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/metadata"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const (
	PluginName            = "pipenv"
	pipfileFile           = "Pipfile"
	pipfileLockFile       = "Pipfile.lock"
	maxConcurrentInstalls = 5
	logFieldFile          = "file"
	pythonRuntimeFmt      = "python@%s"
)

type Plugin struct{}

// Compile-time check to ensure Plugin implements SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// DetectionGlobs implements ecosystems.SCAPlugin.
func (p Plugin) DetectionGlobs() []string {
	return []string{pipfileFile, pipfileLockFile}
}

// InputGlobs implements ecosystems.SCAPlugin. Both files are parsed directly.
func (p Plugin) InputGlobs() []string {
	return []string{pipfileFile, pipfileLockFile}
}

// BuildDepGraphsFromDir discovers and builds dependency graphs for
// Pipenv projects. Build work runs concurrently (bounded by
// maxConcurrentInstalls); onGraph invocations are serialized under a
// mutex to satisfy the SCAPlugin contract.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	if log == nil {
		log = logger.Nop()
	}

	// With component metadata requested this plugin runs ahead of the legacy
	// plugin, so under --file it claims only a Pipfile: legacy owns
	// requirements.txt and setup.py. Without the flag, --file is used as given.
	if tf := options.Global.TargetFile; tf != nil && options.Global.IncludeComponentMetadata &&
		filepath.Base(*tf) != pipfileFile {
		log.Info(ctx, "Skipping pipenv plugin", logger.Attr("targetFile", *tf), logger.Attr("reason", "not a 'Pipfile'"))
		return nil
	}

	// Discover Pipfile files
	files, err := p.discoverPipfiles(ctx, log, dir, options)
	if err != nil {
		return fmt.Errorf("failed to discover Pipfiles: %w", err)
	}

	if len(files) == 0 {
		log.Info(ctx, "No Pipfile files found", logger.Attr("dir", dir))
		return nil
	}

	pythonCommand := pip.ResolvePythonCommand(options.Python.Command, dir)

	var emitMu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentInstalls)

	for _, file := range files {
		g.Go(func() error {
			projectName := pip.GetProjectName(file.RelPath, dir, options.Global.ProjectName)
			result, err := p.buildDepGraphFromPipfile(ctx, log, file, pip.WorkingDir(dir, file, options), pythonCommand, options, projectName)
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
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							ProjectType: "pip",
							TargetFile:  &file.RelPath,
						},
					},
					Error: err,
				}
			}
			if tf := result.ProjectDescriptor.GetTargetFile(); tf != "" {
				result.ProcessedFiles = []string{tf}
			}

			emitMu.Lock()
			defer emitMu.Unlock()
			return onGraph(result)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("error building dependency graphs: %w", err)
	}
	return nil
}

// discoverPipfiles finds Pipfile files based on the provided options.
func (p Plugin) discoverPipfiles(ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions) ([]discovery.FindResult, error) {
	var findOpts []discovery.FindOption

	switch {
	case options.Global.TargetFile != nil:
		// Use specific target file if provided
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(*options.Global.TargetFile),
		}
	case options.Global.AllProjects:
		// Find all Pipfile files recursively
		// ".*" also covers .git and .build, which snyk-python-plugin skips.
		defaultExcludes := []string{".*", "__pycache__", "*.egg-info", "dist", "build", "venv", "node_modules"}
		excludes := make([]string, 0, len(defaultExcludes)+len(options.Global.Exclude)+len(options.Global.ExcludePaths))
		excludes = append(excludes, defaultExcludes...)
		excludes = append(excludes, options.Global.Exclude...)
		excludes = append(excludes, options.Global.ExcludePaths...)
		findOpts = []discovery.FindOption{
			discovery.WithInclude(pipfileFile),
			discovery.WithExcludes(excludes...),
			discovery.WithMaxDepth(options.Global.DetectionDepth),
		}
	default:
		// Default: find Pipfile at root only
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(pipfileFile),
		}
	}

	files, err := discovery.FindFiles(ctx, log, dir, findOpts...)
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
	workDir, pythonCommand string,
	options *ecosystems.SCAPluginOptions,
	projectName string,
) (ecosystems.SCAResult, error) {
	// Same working directory rule as the pip plugin. Pipfile paths are
	// relative to the Pipfile, whatever the working directory.
	pipfileDir := filepath.Dir(file.Path)
	pythonVersion, err := pip.GetPythonVersionForCommand(pythonCommand, workDir)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to detect Python version: %w", err)
	}

	log.Debug(ctx, "Building dependency graph from Pipfile",
		logger.Attr(logFieldFile, file.RelPath),
		logger.Attr("python_version", pythonVersion),
		logger.Attr("project_name", projectName))

	// Parse Pipfile
	pipfile, err := ParsePipfile(file.Path)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to parse Pipfile: %w", err)
	}

	// Check for Pipfile.lock in the same directory
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
	report, err := p.getInstallReport(ctx, log, pipfile, lockfile, pythonCommand, pipfileDir, workDir, options)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to get pip install report: %w", err)
	}

	// Convert report to dependency graph
	// Labels come from the pip report, which names the file pip picked.
	// Pipfile.lock's hashes name no file, so they are not used.
	depGraph, err := report.ToDependencyGraph(ctx, log, projectName, pip.GraphOptions(options)...)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to convert pip report to dependency graph: %w", err)
	}

	log.Info(ctx, "Successfully built dependency graph from Pipfile",
		logger.Attr(logFieldFile, file.RelPath))

	var rootName string
	if rootPkg := depGraph.GetRootPkg(); rootPkg != nil {
		rootName = rootPkg.Info.Name
	}

	return ecosystems.SCAResult{
		DepGraph: depGraph,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       "pip",
				TargetFile:        &file.RelPath,
				RootComponentName: rootName,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName: PluginName,
			VersionBuildInfo: map[string]string{
				metadata.PythonVersion: pythonVersion,
			},
			NormalisedTargetFile: file.RelPath,
		},
	}, nil
}

// getInstallReport runs pip install --dry-run with packages and constraints passed directly.
// The lockfile is always present (either parsed or generated), so we pass only package names
// and let the constraints file (from lockfile) control all version pinning. This avoids
// conflicts where pip sees the same package specified twice with different version constraints.
func (p Plugin) getInstallReport(
	ctx context.Context,
	log logger.Logger,
	pipfile *Pipfile,
	lockfile *PipfileLock,
	pythonCommand, pipfileDir, workDir string,
	options *ecosystems.SCAPluginOptions,
) (*pip.Report, error) {
	includeDevDeps := options.Global.IncludeDev
	// Get package names without version specifiers
	// Without the flag, keep the by-name resolution of path and file
	// entries unchanged: isolated builds copy only the Pipfile and its lock,
	// so those paths do not exist there. Fixing it is tracked separately.
	packages := pipfile.ToPackageNames(includeDevDeps)
	if options.Global.IncludeComponentMetadata {
		var dropped []string
		packages, dropped = pipfile.ToRequirements(includeDevDeps, pipfileDir)
		for _, name := range dropped {
			log.Info(ctx, "Leaving out a Pipfile entry whose local path is not a Python project",
				logger.Attr("package", name), logger.Attr("reason", "path or file missing"))
		}
	}
	if len(packages) == 0 {
		// Return empty report for empty Pipfile (creates depgraph with just root node)
		return &pip.Report{}, nil
	}

	// Get constraints from lockfile (all packages with pinned versions)
	constraints := lockfile.ToConstraints(includeDevDeps)

	// Get pip install report passing packages and constraints directly
	report, err := pip.GetInstallReportFromPackagesWithCommand(ctx, log, packages, constraints,
		options.Python.NoBuildIsolation, pythonCommand, &pip.DefaultExecutor{Dir: workDir})
	if err != nil {
		return nil, fmt.Errorf("pip install report failed: %w", err)
	}
	return report, nil
}
