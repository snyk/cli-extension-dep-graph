package pnpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const (
	PluginName       = "pnpm"
	logFieldLockFile = "lockFile"
	logFieldDir      = "dir"
)

// Plugin implements ecosystems.SCAPlugin for pnpm projects. It shells out to
// `pnpm list --lockfile-only --json` to resolve the dependency graph from the
// lockfile without installing node_modules. Rush monorepos (rush.json) are
// handled by an adapter in rush.go that synthesizes the workspace context Rush
// generates at install time; both adapters produce the same scanTarget shape
// so the runner is uniform.
type Plugin struct {
	executor pnpmListRunner
}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// scanTarget is a single prepared pnpm-list invocation. Every adapter
// (bare-pnpm discovery, Rush staging) collapses its asymmetry into this struct
// so runAndBuild can treat them uniformly.
type scanTarget struct {
	cmdDir          string   // where `pnpm list` runs
	manifestBaseDir string   // base for package.json relative paths
	excludeDir      string   // importer dir to drop (e.g. Rush "rush-common"); "" = none
	processedFiles  []string // files this scan was derived from
	errTargetFile   string   // target file used for an error SCAResult
	cleanup         func()   // tmp-tree teardown; never nil
	// setupErr, when set, short-circuits runAndBuild and surfaces as the
	// target's sole SCAResult — used when an adapter cannot fully stage a
	// target but wants to surface the failure rather than skip silently.
	setupErr error
}

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

	targets, err := collectTargets(ctx, log, dir, options)
	if err != nil {
		return err
	}
	defer func() {
		for _, t := range targets {
			t.cleanup()
		}
	}()
	if len(targets) == 0 {
		return nil
	}

	exec := p.getExecutor()
	for i := range targets {
		results := runAndBuild(ctx, log, exec, &targets[i])
		if err := emit(ctx, log, onGraph, results); err != nil {
			return err
		}
	}
	return nil
}

// collectTargets dispatches to one adapter per scan root. Rush is checked first
// because a Rush root has no scannable pnpm-lock.yaml at the top.
func collectTargets(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]scanTarget, error) {
	if isRushRoot(dir) {
		return rushTargets(ctx, log, dir)
	}
	return pnpmTargets(ctx, log, dir, options)
}

// pnpmTargets discovers pnpm-lock.yaml files per the scan options and produces
// one scan target per lockfile. Bare pnpm needs no staging — cmdDir and
// manifestBaseDir both point at the lockfile's directory.
func pnpmTargets(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]scanTarget, error) {
	files, err := discoverLockFiles(ctx, dir, options)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		log.Debug(ctx, "No pnpm-lock.yaml found", logger.Attr(logFieldDir, dir))
		return nil, nil
	}
	log.Debug(ctx, "Discovered pnpm-lock.yaml files", logger.Attr("count", len(files)))

	targets := make([]scanTarget, 0, len(files))
	for _, file := range files {
		lockDir := filepath.Dir(file.Path)
		errTargetFile := filepath.Join(filepath.Dir(file.RelPath), packageJSONFile)
		targets = append(targets, scanTarget{
			cmdDir:          lockDir,
			manifestBaseDir: lockDir,
			processedFiles:  []string{file.RelPath},
			errTargetFile:   errTargetFile,
			cleanup:         noopCleanup,
		})
	}
	return targets, nil
}

// runAndBuild executes pnpm list for one target and produces SCAResults. A
// pre-baked setupErr short-circuits the run and surfaces as the sole result.
func runAndBuild(ctx context.Context, log logger.Logger, exec pnpmListRunner, t *scanTarget) []ecosystems.SCAResult {
	if t.setupErr != nil {
		return errResult(t.errTargetFile, t.setupErr)
	}

	log.Info(ctx, "Building pnpm dependency graph", logger.Attr(logFieldDir, t.cmdDir))

	output, err := exec.Run(ctx, t.cmdDir)
	if err != nil {
		return errResult(t.errTargetFile, wrapRunError(err))
	}
	defer output.Close()

	data, err := io.ReadAll(output)
	if err != nil {
		return errResult(t.errTargetFile, fmt.Errorf("reading pnpm list output: %w", err))
	}

	var projects []listProject
	if err = json.Unmarshal(data, &projects); err != nil {
		return errResult(t.errTargetFile, fmt.Errorf("parsing pnpm list output: %w", err))
	}

	graphResults, err := buildDepGraphs(t.manifestBaseDir, projects, t.excludeDir)
	if err != nil {
		return errResult(t.errTargetFile, err)
	}

	log.Info(ctx, "Successfully built pnpm dependency graphs", logger.Attr("graphs", len(graphResults)))

	results := make([]ecosystems.SCAResult, len(graphResults))
	for i, gr := range graphResults {
		tf := gr.pkgJSONRelPath
		processed := append(append([]string{}, t.processedFiles...), tf)
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
			ProcessedFiles: processed,
		}
	}
	return results
}

func errResult(targetFile string, err error) []ecosystems.SCAResult {
	tf := targetFile
	return []ecosystems.SCAResult{{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType: pkgManager,
				TargetFile:  &tf,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: tf,
		},
		ProcessedFiles: []string{targetFile},
		Error:          err,
	}}
}

// errTarget builds a scanTarget that carries a setup error in place of a real
// run. runAndBuild short-circuits and turns this into the only SCAResult, so
// setup failures surface as one error result instead of aborting the scan.
func errTarget(targetFile string, err error) scanTarget {
	return scanTarget{
		errTargetFile: targetFile,
		setupErr:      err,
		cleanup:       noopCleanup,
	}
}

func emit(ctx context.Context, log logger.Logger, onGraph ecosystems.OnGraphFunc, results []ecosystems.SCAResult) error {
	for i := range results {
		r := &results[i]
		if r.Error != nil {
			log.Error(ctx, "Failed to build pnpm dependency graph",
				logger.Attr(logFieldLockFile, r.ProjectDescriptor.GetTargetFile()),
				logger.Err(r.Error),
			)
		}
		if err := onGraph(*r); err != nil {
			return err
		}
	}
	return nil
}

func wrapRunError(err error) error {
	if errors.Is(err, errPnpmNotFound) {
		return fmt.Errorf("pnpm is not installed or not in PATH; install pnpm >= %s to scan this project: %w", minPnpmVersion, err)
	}
	if errors.Is(err, errPnpmVersionTooLow) {
		return fmt.Errorf("pnpm >= %s is required for dependency graph resolution: %w", minPnpmVersion, err)
	}
	return fmt.Errorf("running pnpm list: %w", err)
}

func discoverLockFiles(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	if options == nil {
		options = ecosystems.NewPluginOptions()
	}

	switch {
	case options.Global.TargetFile != nil:
		if filepath.Base(*options.Global.TargetFile) != pnpmLockFile {
			return nil, nil
		}
		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering pnpm-lock.yaml files: %w", err)
		}
		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(pnpmLockFile),
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
			return nil, fmt.Errorf("discovering pnpm-lock.yaml files: %w", err)
		}
		return files, nil

	default:
		rootLock := filepath.Join(dir, pnpmLockFile)
		if !fileExists(rootLock) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: rootLock, RelPath: pnpmLockFile}}, nil
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func noopCleanup() {}

// getExecutor returns the configured executor or the production pnpmCmdExecutor.
// The zero-value Plugin{} is valid and uses the production executor.
func (p Plugin) getExecutor() pnpmListRunner {
	if p.executor != nil {
		return p.executor
	}
	return &pnpmCmdExecutor{}
}
