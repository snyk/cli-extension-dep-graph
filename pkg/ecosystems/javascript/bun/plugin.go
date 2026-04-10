package bun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// Plugin implements ecosystems.SCAPlugin for Bun projects.
// It uses `bun why '*' --top` to resolve the full dependency graph without
// bespoke lockfile parsing, requiring bun >= 1.2.19.
type Plugin struct {
	executor bunWhyRunner
}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// BuildDepGraphsFromDir discovers bun.lock files under dir and produces a
// "mega dep graph" for each one — a single SCAResult covering the full workspace.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	if log == nil {
		log = logger.Nop()
	}

	files, err := p.discoverLockFiles(ctx, dir, options)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return &ecosystems.PluginResult{}, nil
	}

	exec := p.getExecutor()

	var results []ecosystems.SCAResult
	var processedFiles []string

	for _, file := range files {
		lockFileAbsDir := filepath.Dir(file.Path)

		result := p.buildResult(ctx, log, file.RelPath, lockFileAbsDir, exec, options)
		results = append(results, result)
		processedFiles = append(processedFiles, file.RelPath)
	}

	return &ecosystems.PluginResult{
		Results:        results,
		ProcessedFiles: processedFiles,
	}, nil
}

func (p Plugin) buildResult(
	ctx context.Context,
	log logger.Logger,
	lockFileRelPath, lockFileAbsDir string,
	exec bunWhyRunner,
	options *ecosystems.SCAPluginOptions,
) ecosystems.SCAResult {
	meta := ecosystems.Metadata{TargetFile: lockFileRelPath}

	log.Info(ctx, "Building bun dependency graph", logger.Attr("lockFile", lockFileRelPath))

	pkgJSON, err := readPackageJSON(lockFileAbsDir)
	if err != nil {
		return ecosystems.SCAResult{Metadata: meta, Error: fmt.Errorf("reading package.json: %w", err)}
	}

	output, err := exec.Run(ctx, lockFileAbsDir)
	if err != nil {
		return ecosystems.SCAResult{Metadata: meta, Error: p.wrapRunError(err)}
	}

	graph, err := parseWhyOutput(output)
	if err != nil {
		return ecosystems.SCAResult{Metadata: meta, Error: fmt.Errorf("parsing bun why output: %w", err)}
	}

	seeds := pkgJSON.directDeps(options.Global.IncludeDev)

	depGraph, err := buildDepGraph(pkgJSON.Name, pkgJSON.Version, seeds, graph, options.Global.AllowOutOfSync)
	if err != nil {
		return ecosystems.SCAResult{Metadata: meta, Error: fmt.Errorf("building dep graph: %w", err)}
	}

	log.Info(ctx, "Successfully built bun dependency graph", logger.Attr("lockFile", lockFileRelPath))

	return ecosystems.SCAResult{
		DepGraph: depGraph,
		Metadata: meta,
	}
}

// wrapRunError converts errors from RunBunWhy into user-facing messages.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errBunNotFound) {
		return fmt.Errorf(
			"bun is not installed or not in PATH; install bun >= %d.%d.%d to scan this project: %w",
			minBunMajor, minBunMinor, minBunPatch, err,
		)
	}

	if errors.Is(err, errBunVersionTooLow) {
		return fmt.Errorf(
			"bun >= %d.%d.%d is required for dependency graph resolution"+
				" (bun why was introduced in v1.2.19): %w",
			minBunMajor, minBunMinor, minBunPatch, err,
		)
	}

	return fmt.Errorf("running bun why: %w", err)
}

func (p Plugin) discoverLockFiles(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	switch {
	case options.Global.TargetFile != nil:
		if filepath.Base(*options.Global.TargetFile) != bunLockFile {
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering bun.lock files: %w", err)
		}

		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(bunLockFile),
			discovery.WithCommonExcludes(),
		}

		if len(options.Global.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
		}

		files, err := discovery.FindFiles(ctx, dir, findOpts...)
		if err != nil {
			return nil, fmt.Errorf("discovering bun.lock files: %w", err)
		}

		return files, nil

	default:
		// Check root directory only; return empty (not an error) if bun.lock is absent.
		rootLock := filepath.Join(dir, bunLockFile)
		if !fileExists(rootLock) {
			return nil, nil
		}

		return []discovery.FindResult{{Path: rootLock, RelPath: bunLockFile}}, nil
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (p Plugin) getExecutor() bunWhyRunner {
	if p.executor != nil {
		return p.executor
	}

	return &bunCmdExecutor{}
}
