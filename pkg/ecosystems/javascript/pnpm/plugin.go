package pnpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
// supported by synthesizing the workspace context Rush generates at install
// time (see rush.go).
type Plugin struct {
	executor pnpmListRunner
}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
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

	exec := p.getExecutor()

	// Rush adapter: a rush.json root has no scannable pnpm-lock.yaml at the
	// root, so handle it before standard discovery.
	if isRushRoot(dir) {
		return emit(ctx, log, onGraph, p.buildRushResults(ctx, log, dir, exec))
	}

	files, err := p.discoverLockFiles(ctx, dir, options)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		log.Debug(ctx, "No pnpm-lock.yaml found", logger.Attr(logFieldDir, dir))
		return nil
	}
	log.Debug(ctx, "Discovered pnpm-lock.yaml files", logger.Attr("count", len(files)))

	for _, file := range files {
		lockDir := filepath.Dir(file.Path)
		errTarget := filepath.Join(filepath.Dir(file.RelPath), packageJSONFile)
		results := p.runAndBuild(ctx, log, exec, &runSpec{
			runDir:        lockDir,
			scanDir:       lockDir,
			baseProcessed: []string{file.RelPath},
			errTargetFile: errTarget,
		})
		if err := emit(ctx, log, onGraph, results); err != nil {
			return err
		}
	}

	return nil
}

// buildRushResults stages the Rush workspace then resolves it. npm/yarn-backed
// or subspaces Rush repos are skipped (logged, no results) per the pnpm-only
// scope; setup failures surface as an error result.
func (p Plugin) buildRushResults(ctx context.Context, log logger.Logger, rushDir string, exec pnpmListRunner) []ecosystems.SCAResult {
	log.Info(ctx, "Building Rush + pnpm dependency graphs", logger.Attr(logFieldDir, rushDir))

	folders, err := rushProjectFolders(rushDir)
	if err != nil {
		if errors.Is(err, errRushNotPnpm) || errors.Is(err, errRushSubspaces) {
			log.Info(ctx, "Skipping Rush workspace", logger.Attr("reason", err.Error()))
			return nil
		}
		return errResult(rushJSONFile, fmt.Errorf("reading rush.json: %w", err))
	}

	runDir, scanRoot, skipped, cleanup, err := stageRushWorkspace(rushDir, folders)
	if err != nil {
		return errResult(rushJSONFile, err)
	}
	defer cleanup()

	if len(skipped) > 0 {
		// User-visible surfacing of skips is part of the deferred FF+wiring work
		// (#3); for now log so a stale/renamed project folder doesn't silently
		// vanish from a scan that otherwise succeeds.
		log.Info(ctx, "Skipping Rush projects with no readable package.json",
			logger.Attr("projects", strings.Join(skipped, ", ")))
	}

	return p.runAndBuild(ctx, log, exec, &runSpec{
		runDir:        runDir,
		scanDir:       scanRoot,
		skipDir:       runDir, // the synthetic "rush-common" aggregate lives here
		baseProcessed: []string{rushJSONFile, filepath.FromSlash(rushLockfilePath)},
		errTargetFile: rushJSONFile,
	})
}

// runSpec parameterises a single pnpm-list run.
type runSpec struct {
	runDir        string   // where pnpm runs
	scanDir       string   // base for package.json relative paths
	skipDir       string   // importer dir to omit (e.g. the rush-common aggregate); "" skips nothing
	baseProcessed []string // files every result was derived from
	errTargetFile string   // target file for an error result
}

func (p Plugin) runAndBuild(ctx context.Context, log logger.Logger, exec pnpmListRunner, spec *runSpec) []ecosystems.SCAResult {
	log.Info(ctx, "Building pnpm dependency graph", logger.Attr(logFieldDir, spec.runDir))

	output, err := exec.Run(ctx, spec.runDir)
	if err != nil {
		return errResult(spec.errTargetFile, p.wrapRunError(err))
	}
	defer output.Close()

	data, err := io.ReadAll(output)
	if err != nil {
		return errResult(spec.errTargetFile, fmt.Errorf("reading pnpm list output: %w", err))
	}

	var projects []listProject
	if err = json.Unmarshal(data, &projects); err != nil {
		return errResult(spec.errTargetFile, fmt.Errorf("parsing pnpm list output: %w", err))
	}

	graphResults, err := buildDepGraphs(spec.scanDir, projects, spec.skipDir)
	if err != nil {
		return errResult(spec.errTargetFile, err)
	}

	log.Info(ctx, "Successfully built pnpm dependency graphs", logger.Attr("graphs", len(graphResults)))

	results := make([]ecosystems.SCAResult, len(graphResults))
	for i, gr := range graphResults {
		tf := gr.pkgJSONRelPath
		processed := append(append([]string{}, spec.baseProcessed...), tf)
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

func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errPnpmNotFound) {
		return fmt.Errorf("pnpm is not installed or not in PATH; install pnpm >= %s to scan this project: %w", minPnpmVersion, err)
	}
	if errors.Is(err, errPnpmVersionTooLow) {
		return fmt.Errorf("pnpm >= %s is required for dependency graph resolution: %w", minPnpmVersion, err)
	}
	return fmt.Errorf("running pnpm list: %w", err)
}

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

// getExecutor returns the configured executor or the production pnpmCmdExecutor.
// The zero-value Plugin{} is valid and uses the production executor.
func (p Plugin) getExecutor() pnpmListRunner {
	if p.executor != nil {
		return p.executor
	}
	return &pnpmCmdExecutor{}
}
