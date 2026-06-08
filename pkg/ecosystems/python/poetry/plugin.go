package poetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const (
	projectType      = "poetry"
	logFieldLockFile = "lockFile"
)

// Plugin is the SCAPlugin implementation for Poetry. The zero value is
// valid and uses the real poetry binary; tests inject a fake runner.
type Plugin struct {
	executor poetryRunner
}

// Compile-time interface assertion.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers poetry.lock files under dir and
// produces one dep graph per discovered project. The behaviour mirrors
// the sibling python/uv plugin: in the default (no --all-projects)
// case we only look at dir/poetry.lock; --target-file and --all-projects
// behave the same as in pip/uv/bun.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	if log == nil {
		log = logger.Nop()
	}
	if options == nil {
		options = ecosystems.NewPluginOptions()
	}

	files, err := p.discoverLockFiles(ctx, dir, options)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		log.Debug(ctx, "No poetry.lock files found", logger.Attr("dir", dir))
		return nil
	}

	runner := p.getRunner()

	for _, file := range files {
		result := p.buildResult(ctx, log, dir, file, options, runner)
		if emitErr := onGraph(result); emitErr != nil {
			return emitErr
		}
		// Without --all-projects we only process the first match — same
		// pattern as python/uv and python/pip.
		if !options.Global.AllProjects {
			break
		}
	}
	return nil
}

// buildResult builds a single SCAResult for one discovered poetry.lock.
// All error paths still produce an SCAResult (with .Error set) so the
// caller can surface per-project failures without aborting siblings.
func (p Plugin) buildResult(
	ctx context.Context,
	log logger.Logger,
	scanDir string,
	file discovery.FindResult,
	options *ecosystems.SCAPluginOptions,
	runner poetryRunner,
) ecosystems.SCAResult {
	lockFileRel := file.RelPath                       // e.g. "poetry.lock" or "svc/poetry.lock"
	lockFileAbsDir := filepath.Dir(file.Path)         // absolute dir holding poetry.lock
	lockFileRelDir := filepath.Dir(lockFileRel)       // relative dir for processedFiles
	manifestRel := manifestRelPath(lockFileRel)       // sibling pyproject.toml (relative)

	errResult := func(err error) ecosystems.SCAResult {
		mf := manifestRel
		return ecosystems.SCAResult{
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType: projectType,
					TargetFile:  &mf,
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName:           PluginName,
				NormalisedTargetFile: manifestRel,
			},
			ProcessedFiles: processedFilesFor(lockFileRelDir),
			Error:          err,
		}
	}

	log.Info(ctx, "Building poetry dependency graph", logger.Attr(logFieldLockFile, lockFileRel))

	manifest, err := readPyproject(lockFileAbsDir)
	if err != nil {
		return errResult(fmt.Errorf("reading pyproject.toml: %w", err))
	}

	// Resolve the root package name. scanDir for the fallback is the
	// directory containing poetry.lock — not the top-level scan root —
	// so nested projects in --all-projects mode get a useful name.
	root := resolveRootPkg(manifest, lockFileAbsDir, options.Global.ProjectName)

	stream, err := runner.Run(ctx, lockFileAbsDir, options.Global.IncludeDev)
	if err != nil {
		return errResult(p.wrapRunError(err))
	}
	defer stream.Close()

	tree, err := parseTreeOutput(stream)
	if err != nil {
		return errResult(fmt.Errorf("parsing poetry show output: %w", err))
	}

	dg, err := buildDepGraphFromTree(ctx, log, root, tree)
	if err != nil {
		return errResult(fmt.Errorf("building dep graph: %w", err))
	}

	log.Info(ctx, "Built poetry dependency graph",
		logger.Attr(logFieldLockFile, lockFileRel),
		logger.Attr("root", root.Name),
		logger.Attr("top_level", len(tree)),
	)

	var rootName string
	if rp := dg.GetRootPkg(); rp != nil {
		rootName = rp.Info.Name
	}

	mf := manifestRel
	return ecosystems.SCAResult{
		DepGraph: dg,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       projectType,
				TargetFile:        &mf,
				RootComponentName: rootName,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: manifestRel,
			VersionBuildInfo:     map[string]string{},
		},
		ProcessedFiles: processedFilesFor(lockFileRelDir),
	}
}

// wrapRunError adds user-actionable context to executor sentinels so
// the surfaced error explains the fix.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errPoetryNotFound) {
		return fmt.Errorf(
			"poetry is not installed or not in PATH; install poetry >= %d.%d to scan this project: %w",
			minPoetryMajor, minPoetryMinor, err,
		)
	}
	if errors.Is(err, errPoetryVersionTooLow) {
		return fmt.Errorf(
			"poetry >= %d.%d is required to resolve poetry.lock projects: %w",
			minPoetryMajor, minPoetryMinor, err,
		)
	}
	return fmt.Errorf("running poetry show: %w", err)
}

// discoverLockFiles finds poetry.lock files under dir per the options.
// Same convention as python/uv: --target-file pins the exact path,
// --all-projects walks, default is just dir/poetry.lock.
func (p Plugin) discoverLockFiles(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	switch {
	case options.Global.TargetFile != nil:
		if filepath.Base(*options.Global.TargetFile) != LockFileName {
			// Not a poetry.lock — silently no-op so other plugins can claim it.
			return nil, nil
		}
		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering poetry.lock: %w", err)
		}
		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(LockFileName),
			discovery.WithCommonExcludes(),
		}
		if len(options.Global.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
		}
		if len(options.Global.ExcludePaths) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.ExcludePaths...))
		}
		files, err := discovery.FindFiles(ctx, dir, findOpts...)
		if err != nil {
			return nil, fmt.Errorf("discovering poetry.lock files: %w", err)
		}
		return files, nil

	default:
		rootLock := filepath.Join(dir, LockFileName)
		if !fileExists(rootLock) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: rootLock, RelPath: LockFileName}}, nil
	}
}

// manifestRelPath returns the relative path to the pyproject.toml that
// sits alongside lockFileRel, preserving the conventional "no leading
// dot" form when the lockfile lives in the scan root.
func manifestRelPath(lockFileRel string) string {
	dir := filepath.Dir(lockFileRel)
	if dir == "." {
		return PyprojectTomlFileName
	}
	return filepath.Join(dir, PyprojectTomlFileName)
}

// processedFilesFor returns the lockfile + manifest paths, scoped to
// the directory holding poetry.lock.
func processedFilesFor(lockFileRelDir string) []string {
	if lockFileRelDir == "." || lockFileRelDir == "" {
		return []string{LockFileName, PyprojectTomlFileName}
	}
	return []string{
		filepath.Join(lockFileRelDir, LockFileName),
		filepath.Join(lockFileRelDir, PyprojectTomlFileName),
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// getRunner returns the configured runner (tests) or the production
// shell-out executor (default Plugin{} zero value).
func (p Plugin) getRunner() poetryRunner {
	if p.executor != nil {
		return p.executor
	}
	return &poetryCmdExecutor{}
}
