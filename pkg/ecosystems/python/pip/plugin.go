package pip

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	snyk_ecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/metadata"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const (
	PluginName            = "pip"
	requirementsFile      = "requirements.txt"
	maxConcurrentInstalls = 5
	logFieldFile          = "file"
)

type Plugin struct{}

func (p Plugin) GetName() string {
	return PluginName
}

// DetectionGlobs implements ecosystems.SCAPlugin.
func (p Plugin) DetectionGlobs() []string {
	return []string{requirementsFile}
}

// InputGlobs implements ecosystems.SCAPlugin. Requirements files include others
// with -r and -c under any name, and a local path requirement is read from its
// project files.
func (p Plugin) InputGlobs() []string {
	return []string{"*.txt", "pyproject.toml", "setup.py", "setup.cfg"}
}

// Compile-time check to ensure Plugin implements SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// BuildDepGraphsFromDir discovers and builds dependency graphs for
// Python pip projects. Build work runs concurrently (bounded by
// maxConcurrentInstalls) but onGraph invocations are serialized under
// a mutex to satisfy the SCAPlugin contract — callbacks need not be
// goroutine-safe.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	if log == nil {
		log = logger.Nop()
	}

	// With component metadata requested, --file claims only requirements.txt:
	// the legacy plugin owns Pipfile, setup.py and non-standard requirements
	// names (those need --package-manager=pip there). Without the flag,
	// --file is used as given, as before.
	if tf := options.Global.TargetFile; tf != nil && options.Global.IncludeComponentMetadata &&
		filepath.Base(*tf) != requirementsFile {
		log.Info(ctx, "Skipping pip plugin", logger.Attr("targetFile", *tf), logger.Attr("reason", "not a 'requirements.txt' file"))
		return nil
	}

	// Discover requirements.txt files
	files, err := p.discoverRequirementsFiles(ctx, log, dir, options)
	if err != nil {
		return fmt.Errorf("failed to discover requirements files: %w", err)
	}

	if len(files) == 0 {
		log.Info(ctx, "No requirements.txt files found", logger.Attr("dir", dir))
		return nil
	}

	// Get Python runtime version. With component metadata requested it is
	// probed in the scan root, where pip runs; otherwise in the process's
	// working directory, as before.
	pythonVersion, err := GetPythonVersionIn(WorkingDir(dir, discovery.FindResult{RelPath: requirementsFile}, options))
	if err != nil {
		return fmt.Errorf("failed to detect Python version: %w", err)
	}

	// emitMu serializes onGraph calls; the first non-nil onGraph error
	// is captured and surfaced to errgroup to cancel sibling builds.
	var emitMu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrentInstalls)

	for _, file := range files {
		g.Go(func() error {
			projectName := GetProjectName(file.RelPath, dir, options.Global.ProjectName)
			result, err := p.buildDepGraphFromFile(ctx, log, file, WorkingDir(dir, file, options), pythonVersion, options, projectName)
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
						},
					},
					Error: err,
				}
			}
			result.ProcessedFiles = []string{file.RelPath}

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

// discoverRequirementsFiles finds requirements.txt files based on the provided options.
func (p Plugin) discoverRequirementsFiles(
	ctx context.Context, log logger.Logger, dir string, options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
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
		defaultExcludes := []string{".*", "__pycache__", "*.egg-info", "dist", "build", "venv"}
		excludes := make([]string, 0, len(defaultExcludes)+len(options.Global.Exclude)+len(options.Global.ExcludePaths))
		excludes = append(excludes, defaultExcludes...)
		excludes = append(excludes, options.Global.Exclude...)
		excludes = append(excludes, options.Global.ExcludePaths...)
		findOpts = []discovery.FindOption{
			discovery.WithInclude(requirementsFile),
			discovery.WithExcludes(excludes...),
			discovery.WithMaxDepth(options.Global.DetectionDepth),
		}
	default:
		// Default: find requirements.txt at root only
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(requirementsFile),
		}
	}

	files, err := discovery.FindFiles(ctx, log, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to find files: %w", err)
	}
	return files, nil
}

// GetProjectName determines the project name based on the file path.
// It uses the directory name containing the file. For example:
//   - "project/test/requirements.txt" -> "test"
//   - "project/requirements.txt" -> "project"
//   - "requirements.txt" (with scanDir="/path/to/myproject") -> "myproject"
func GetProjectName(filePath, scanDir string, override *string) string {
	if override != nil && *override != "" {
		return *override
	}

	// Extract the directory name from the file path
	dir := filepath.Dir(filePath)
	projectName := filepath.Base(dir)

	// If we're at the root or the directory name is ".", use the scan directory name
	if projectName == "." || projectName == "/" || projectName == "" {
		return filepath.Base(scanDir)
	}

	return projectName
}

// buildDepGraphFromFile builds a dependency graph from a requirements.txt file.
func (p Plugin) buildDepGraphFromFile(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	workDir, pythonVersion string,
	options *ecosystems.SCAPluginOptions,
	projectName string,
) (ecosystems.SCAResult, error) {
	log.Debug(ctx, "Building dependency graph",
		logger.Attr(logFieldFile, file.RelPath),
		logger.Attr("python_version", pythonVersion),
		logger.Attr("project_name", projectName))

	// Get pip install report (dry-run, no actual installation)
	report, err := GetInstallReportWithExecutor(ctx, log, file.Path, options.Python.NoBuildIsolation,
		&DefaultExecutor{Dir: workDir})
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to get pip install report for %s: %w", file.RelPath, err)
	}

	// Convert report to dependency graph
	depGraph, err := report.ToDependencyGraph(ctx, log, projectName, GraphOptions(options)...)
	if err != nil {
		return ecosystems.SCAResult{}, fmt.Errorf("failed to convert pip report to dependency graph for %s: %w", file.RelPath, err)
	}

	log.Debug(ctx, "Successfully built dependency graph",
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

// GraphOptions maps plugin options onto ToDependencyGraph options, so the
// pip and pipenv plugins label graphs the same way.
func GraphOptions(options *ecosystems.SCAPluginOptions) []GraphOption {
	if options.Global.IncludeComponentMetadata {
		return []GraphOption{WithComponentMetadata()}
	}
	return nil
}

// WorkingDir is where pip runs for a manifest; empty means the process's
// working directory, which is what it is without component metadata, as
// before. pip resolves bare and -e paths in a requirements file (`-e .`,
// `./pkg`) against its working directory, while -r and -c are relative to
// the file, so with the flag a wrong directory means a wrong hash.
//
// With the flag, under --file or for a manifest at the root, that is the
// scan root, as when the CLI runs from it: `--file=deploy/requirements.txt`
// containing `-e .` names the root project. A sub-manifest found by
// --all-projects resolves from its own directory, as it would when run there.
func WorkingDir(root string, file discovery.FindResult, options *ecosystems.SCAPluginOptions) string {
	if !options.Global.IncludeComponentMetadata {
		return ""
	}
	if options.Global.TargetFile == nil && filepath.Dir(file.RelPath) != "." {
		return filepath.Dir(file.Path)
	}
	if abs, err := filepath.Abs(root); err == nil {
		return abs
	}
	return root
}

// GetPythonVersion detects the installed Python version.
func GetPythonVersion() (string, error) {
	return GetPythonVersionIn("")
}

// GetPythonVersionIn is GetPythonVersion run in dir; empty means the
// process's working directory.
func GetPythonVersionIn(dir string) (string, error) {
	// Try python3 first (more common on Unix systems)
	if version, err := execPythonVersion("python3", dir); err == nil {
		return version, nil
	}

	// Fall back to python (Windows or systems with python pointing to Python 3)
	if version, err := execPythonVersion("python", dir); err == nil {
		return version, nil
	}

	// Python not found in PATH
	return "", snyk_ecosystems.NewInstallationFailureError(
		"Python is not installed or not found in PATH. Please install Python 3 and ensure it is available in your system PATH.",
	)
}

// execPythonVersion executes python --version and parses the output.
// An empty dir runs it in the process's working directory.
func execPythonVersion(pythonCmd, dir string) (string, error) {
	cmd := exec.Command(pythonCmd, "--version") //nolint:noctx // No context available in this function
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute %s --version: %w", pythonCmd, err)
	}

	// Parse "Python 3.11.5" -> "3.11.5"
	versionStr := strings.TrimSpace(string(output))
	versionStr = strings.TrimPrefix(versionStr, "Python ")

	return versionStr, nil
}
