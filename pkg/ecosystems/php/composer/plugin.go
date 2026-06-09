package composer

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
	// PluginName is the SCA plugin identifier surfaced in result metadata.
	PluginName       = "composer"
	logFieldLockFile = "lockFile"
)

// Plugin implements ecosystems.SCAPlugin for composer (PHP) projects.
//
// It shells out to `composer show --locked --tree --no-interaction --no-ansi`
// against composer.lock — no vendor/ required, no install triggered. This
// outsources lockfile interpretation (including replace/conflict/provide,
// branch-alias resolution, and platform requirement validation) to composer
// itself, eliminating a class of bespoke-parser bugs that affected the
// legacy snyk-php-plugin + composer-lockfile-parser stack.
//
// Requires composer >= 2.0.0 in PATH.
//
// When BuildDepGraphsFromDir is called with a non-nil SCAPluginOptions, its
// Global.IncludeDev field controls whether composer's `--no-dev` flag is
// passed. Default (IncludeDev=false, also the legacy Snyk CLI default) maps
// to `--no-dev`, excluding require-dev entries from the graph. The
// Plugin.IncludeDev field acts as a direct-caller convenience that forces
// dev deps into the graph regardless of options.
type Plugin struct {
	executor   composerShowRunner
	IncludeDev bool
}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// GetName returns the plugin identifier.
func (p Plugin) GetName() string {
	return PluginName
}

// runOptions translates Plugin.IncludeDev plus caller-supplied
// SCAPluginOptions into the executor's RunOptions.
//
// The orchestrator-driven path passes a non-nil SCAPluginOptions whose
// Global.IncludeDev field carries the user's --dev intent. We forward it
// directly. Plugin.IncludeDev=true forces inclusion regardless of options
// so direct callers can opt in without constructing a full
// SCAPluginOptions.
func (p Plugin) runOptions(options *ecosystems.SCAPluginOptions) RunOptions {
	out := RunOptions{IncludeDev: p.IncludeDev}
	if options != nil && options.Global.IncludeDev {
		out.IncludeDev = true
	}
	return out
}

// BuildDepGraphsFromDir discovers composer.lock files under dir and
// produces one dep graph per lockfile. Composer projects today do not
// emit per-workspace graphs (composer monorepo support is rare in the
// audited fixture corpus) so each lockfile yields exactly one result.
//
// Each result is emitted via onGraph as soon as it's built.
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

	files, err := p.discoverLockFiles(ctx, dir, options)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		log.Debug(ctx, "No composer.lock files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered composer.lock files", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	for _, file := range files {
		lockFileAbsDir := filepath.Dir(file.Path)

		fileResults := p.buildResults(ctx, log, file.RelPath, lockFileAbsDir, exec, options)
		for i := range fileResults {
			r := &fileResults[i]
			if r.Error != nil {
				log.Error(ctx, "Failed to build composer dependency graph",
					logger.Attr(logFieldLockFile, file.RelPath),
					logger.Err(r.Error),
				)
			}
			r.ProcessedFiles = append(r.ProcessedFiles, file.RelPath)
			if tf := r.ProjectDescriptor.GetTargetFile(); tf != "" && tf != file.RelPath {
				r.ProcessedFiles = append(r.ProcessedFiles, tf)
			}
			if err := onGraph(*r); err != nil {
				return err
			}
		}
	}

	return nil
}

// buildResults runs composer show against the directory holding the
// lockfile and assembles the corresponding SCAResult(s). The
// per-lockfile slice has length 1 today; the slice shape is retained
// for symmetry with the npm/yarn plugins should workspace support land.
func (p Plugin) buildResults(
	ctx context.Context,
	log logger.Logger,
	lockFileRelPath, lockFileAbsDir string,
	exec composerShowRunner,
	options *ecosystems.SCAPluginOptions,
) []ecosystems.SCAResult {
	lockFileDir := filepath.Dir(lockFileRelPath)
	rootTargetFile := filepath.Join(lockFileDir, composerJSONFile)

	errResult := func(err error) []ecosystems.SCAResult {
		return []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType: pkgManager,
					TargetFile:  &rootTargetFile,
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName:           PluginName,
				NormalisedTargetFile: rootTargetFile,
			},
			Error: err,
		}}
	}

	log.Info(ctx, "Building composer dependency graph", logger.Attr(logFieldLockFile, lockFileRelPath))

	composerJSON, err := readComposerJSON(lockFileAbsDir)
	if err != nil {
		return errResult(fmt.Errorf("reading composer.json: %w", err))
	}

	output, err := exec.Run(ctx, lockFileAbsDir, p.runOptions(options))
	if err != nil {
		return errResult(p.wrapRunError(err))
	}
	defer func() { _ = output.Close() }()

	parsed, err := parseTreeOutput(output)
	if err != nil {
		return errResult(fmt.Errorf("parsing composer show output: %w", err))
	}

	rootName := rootProjectName(composerJSON, lockFileAbsDir)
	rootVersion := rootProjectVersion(composerJSON)

	log.Debug(ctx, "Parsed composer show output",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr("topLevelDeps", len(parsed.RootDeps)),
		logger.Attr("totalNodes", len(parsed.Graph)),
	)

	graphResults, err := buildDepGraphs(rootName, rootVersion, parsed)
	if err != nil {
		return errResult(fmt.Errorf("building dep graphs: %w", err))
	}

	log.Info(ctx, "Successfully built composer dependency graphs",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr("graphs", len(graphResults)),
	)

	results := make([]ecosystems.SCAResult, len(graphResults))
	for i, gr := range graphResults {
		tf := filepath.Join(lockFileDir, gr.composerJSONRelDir, composerJSONFile)
		results[i] = ecosystems.SCAResult{
			DepGraph: gr.graph,
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType:       pkgManager,
					TargetFile:        &tf,
					RootComponentName: gr.graph.GetRootPkg().Info.Name,
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName:           PluginName,
				VersionBuildInfo:     map[string]string{},
				NormalisedTargetFile: tf,
			},
		}
	}

	return results
}

// wrapRunError converts errors from composerCmdExecutor.Run into
// user-facing messages. Sentinel errors get bespoke wording; everything
// else is surfaced verbatim with a "composer show" prefix.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errComposerNotFound) {
		return fmt.Errorf(
			"composer is not installed or not in PATH; install composer >= %s to scan this project: %w",
			minComposerVersion, err,
		)
	}
	if errors.Is(err, errComposerVersionTooLow) {
		return fmt.Errorf(
			"composer >= %s is required for dependency graph resolution: %w",
			minComposerVersion, err,
		)
	}
	return fmt.Errorf("running composer show: %w", err)
}

// discoverLockFiles applies the standard SCAPluginOptions-driven discovery
// rules (TargetFile, AllProjects, or single-root) to locate composer.lock
// files under dir.
func (p Plugin) discoverLockFiles(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	if options == nil {
		options = ecosystems.NewPluginOptions()
	}

	switch {
	case options.Global.TargetFile != nil:
		if filepath.Base(*options.Global.TargetFile) != composerLockFile {
			return nil, nil
		}
		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering composer.lock files: %w", err)
		}
		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(composerLockFile),
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
			return nil, fmt.Errorf("discovering composer.lock files: %w", err)
		}
		return files, nil

	default:
		rootLock := filepath.Join(dir, composerLockFile)
		if !fileExists(rootLock) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: rootLock, RelPath: composerLockFile}}, nil
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// getExecutor returns the configured executor or the production
// composerCmdExecutor. The Plugin{} zero value is valid and uses the
// production executor by default.
func (p Plugin) getExecutor() composerShowRunner {
	if p.executor != nil {
		return p.executor
	}
	return &composerCmdExecutor{}
}
