package bun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

const logFieldLockFile = "lockFile"

// Plugin implements ecosystems.SCAPlugin for Bun projects.
// It uses `bun why '*' --top` to resolve the full dependency graph without
// bespoke lockfile parsing, requiring bun >= 1.2.19.
type Plugin struct {
	executor bunWhyRunner
}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// BuildDepGraphsFromDir discovers bun.lock files under dir and produces dep
// graphs for each one. Workspace projects yield one SCAResult per workspace
// package plus one for the root; non-workspace projects yield a single result.
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
		log.Debug(ctx, "No bun.lock files found", logger.Attr("dir", dir))
		return &ecosystems.PluginResult{}, nil
	}

	log.Debug(ctx, "Discovered bun.lock files", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	var results []ecosystems.SCAResult
	var processedFiles []string

	for _, file := range files {
		lockFileAbsDir := filepath.Dir(file.Path)

		fileResults := p.buildResults(ctx, log, file.RelPath, lockFileAbsDir, exec)
		for _, r := range fileResults {
			if r.Error != nil {
				log.Error(ctx, "Failed to build bun dependency graph",
					logger.Attr(logFieldLockFile, file.RelPath),
					logger.Err(r.Error),
				)
			}
		}
		results = append(results, fileResults...)
		processedFiles = append(processedFiles, file.RelPath)
	}

	return &ecosystems.PluginResult{
		Results:        results,
		ProcessedFiles: processedFiles,
	}, nil
}

func (p Plugin) buildResults(
	ctx context.Context,
	log logger.Logger,
	lockFileRelPath, lockFileAbsDir string,
	exec bunWhyRunner,
) []ecosystems.SCAResult {
	meta := ecosystems.Metadata{TargetFile: lockFileRelPath}

	errResult := func(err error) []ecosystems.SCAResult {
		return []ecosystems.SCAResult{{Metadata: meta, Error: err}}
	}

	log.Info(ctx, "Building bun dependency graph", logger.Attr(logFieldLockFile, lockFileRelPath))

	pkgJSON, err := readPackageJSON(lockFileAbsDir)
	if err != nil {
		return errResult(fmt.Errorf("reading package.json: %w", err))
	}

	output, err := exec.Run(ctx, lockFileAbsDir)
	if err != nil {
		return errResult(p.wrapRunError(err))
	}

	out, err := parseWhyOutput(ctx, log, output)
	if err != nil {
		// Drain the reader so the subprocess goroutine in bunCmdExecutor can finish.
		if _, drainErr := io.Copy(io.Discard, output); drainErr != nil {
			log.Debug(ctx, "draining reader after parse error", logger.Err(drainErr))
		}
		return errResult(fmt.Errorf("parsing bun why output: %w", err))
	}

	log.Debug(ctx, "Parsed bun why output", logger.Attr(logFieldLockFile, lockFileRelPath), logger.Attr("packages", len(out.Graph)))

	graphs, err := buildDepGraphs(pkgJSON.Name, pkgJSON.Version, out)
	if err != nil {
		return errResult(fmt.Errorf("building dep graphs: %w", err))
	}

	log.Info(ctx, "Successfully built bun dependency graphs", logger.Attr(logFieldLockFile, lockFileRelPath), logger.Attr("graphs", len(graphs)))

	results := make([]ecosystems.SCAResult, len(graphs))
	for i, g := range graphs {
		results[i] = ecosystems.SCAResult{DepGraph: g, Metadata: meta}
	}

	return results
}

// wrapRunError converts errors from RunBunWhy into user-facing messages.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errBunNotFound) {
		return fmt.Errorf(
			"bun is not installed or not in PATH; install bun >= %s to scan this project: %w",
			minBunVersion, err,
		)
	}

	if errors.Is(err, errBunVersionTooLow) {
		return fmt.Errorf(
			"bun >= %s is required for dependency graph resolution"+
				" (bun why was introduced in v1.2.19): %w",
			minBunVersion, err,
		)
	}

	return fmt.Errorf("running bun why: %w", err)
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

// getExecutor returns the configured executor or the production bunCmdExecutor.
// Plugin{} zero-value is valid and uses the production executor by default.
func (p Plugin) getExecutor() bunWhyRunner {
	if p.executor != nil {
		return p.executor
	}

	return &bunCmdExecutor{}
}
