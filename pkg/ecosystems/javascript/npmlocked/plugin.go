package npmlocked

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
	PluginName       = "npm"
	logFieldLockFile = "lockFile"
)

// Plugin implements ecosystems.SCAPlugin for npm projects.
//
// It shells out to `npm ls --json` (with version-appropriate flags) against
// the lockfile + manifest only — no node_modules required, no install. This
// outsources lockfile interpretation to npm itself, eliminating a class of
// bespoke-parser bugs.
//
// Requires npm >= 6 in PATH.
//
// Behavior is configured via SCAPluginOptions passed to BuildDepGraphsFromDir:
// Global.IncludeDev=false (the zero value, also the legacy Snyk CLI default)
// suppresses dev deps via `--omit=dev`; IncludeDev=true keeps them in the
// graph.
//
// No knobs for optional / peer deps: the Snyk CLI doesn't expose them either
// (optional deps are hardcoded on, peer-dep handling is hardcoded inside the
// legacy parser). If those ever become user-controllable upstream, extend
// RunOptions to match.
type Plugin struct {
	executor npmLsRunner
}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers package-lock.json files under dir and
// produces dep graphs for each one. Workspace projects yield one SCAResult
// per workspace package plus one for the root; non-workspace projects yield a
// single result.
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
	if options == nil {
		options = ecosystems.NewPluginOptions()
	}

	files, err := p.discoverLockFiles(ctx, dir, options)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		log.Debug(ctx, "No npm lockfile found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered npm lockfiles", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	for _, file := range files {
		lockFileAbsDir := filepath.Dir(file.Path)

		fileResults := p.buildResults(ctx, log, file.RelPath, lockFileAbsDir, exec, options)
		for i := range fileResults {
			r := &fileResults[i]
			if r.Error != nil {
				log.Error(ctx, "Failed to build npm dependency graph",
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

func (p Plugin) buildResults(
	ctx context.Context,
	log logger.Logger,
	lockFileRelPath, lockFileAbsDir string,
	exec npmLsRunner,
	options *ecosystems.SCAPluginOptions,
) []ecosystems.SCAResult {
	lockFileDir := filepath.Dir(lockFileRelPath)
	rootTargetFile := filepath.Join(lockFileDir, packageJSONFile)

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

	log.Info(ctx, "Building npm dependency graph", logger.Attr(logFieldLockFile, lockFileRelPath))

	pkgJSON, err := readPackageJSON(lockFileAbsDir)
	if err != nil {
		return errResult(fmt.Errorf("reading package.json: %w", err))
	}

	output, err := exec.Run(ctx, lockFileAbsDir, RunOptions{OmitDev: !options.Global.IncludeDev})
	if err != nil {
		return errResult(p.wrapRunError(err))
	}
	defer output.Close()

	parsed, err := parseListOutput(output)
	if err != nil {
		return errResult(fmt.Errorf("parsing npm ls output: %w", err))
	}

	// Prefer the package.json's name/version as the graph root identity, but
	// fall back to whatever npm reported if package.json omits them. npm ls
	// sets these from package.json itself, so they're usually equivalent.
	rootName := pkgJSON.Name
	if rootName == "" {
		rootName = parsed.Name
	}
	rootVersion := pkgJSON.Version
	if rootVersion == "" {
		rootVersion = parsed.Version
	}
	if rootVersion == "" {
		rootVersion = defaultVersion
	}

	log.Debug(ctx, "Parsed npm ls output",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr("topLevelDeps", len(parsed.Dependencies)),
	)

	// npm reports out-of-sync lockfiles, missing deps, etc. via a structured
	// `problems` array alongside a partial-but-usable tree. Surface them so
	// customers see the actionable detail ("missing X required by Y") instead
	// of an opaque scan. Logger interface has no Warn; Info is the closest
	// level — these are not errors (the scan succeeded) but are user-actionable.
	for _, problem := range parsed.Problems {
		log.Info(ctx, "npm reported a lockfile problem",
			logger.Attr(logFieldLockFile, lockFileRelPath),
			logger.Attr("problem", problem),
		)
	}

	// Only split into per-workspace graphs when the caller opted into
	// multi-project scanning. Without --all-projects, the legacy CLI emits one
	// graph per invocation; emitting N+1 here would silently expand a customer's
	// Snyk project count. With workspacePaths nil, the root graph walks
	// transitively through workspace packages instead of stopping at them.
	var graphWorkspacePaths, graphWorkspaceVersions map[string]string
	if options.Global.AllProjects {
		graphWorkspacePaths = readWorkspacePaths(lockFileAbsDir)
		graphWorkspaceVersions = readWorkspaceVersions(lockFileAbsDir, graphWorkspacePaths)
	}

	graphResults, err := buildDepGraphs(rootName, rootVersion, parsed, graphWorkspacePaths, graphWorkspaceVersions)
	if err != nil {
		return errResult(fmt.Errorf("building dep graphs: %w", err))
	}

	log.Info(ctx, "Successfully built npm dependency graphs",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr("graphs", len(graphResults)),
	)

	results := make([]ecosystems.SCAResult, len(graphResults))
	for i, gr := range graphResults {
		tf := filepath.Join(lockFileDir, gr.pkgJSONRelPath)
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

// parseListOutput consumes a streaming `npm ls --json` reader and decodes it.
func parseListOutput(r io.Reader) (*listResponse, error) {
	var parsed listResponse
	if err := json.NewDecoder(r).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decoding npm ls JSON: %w", err)
	}
	return &parsed, nil
}

// wrapRunError converts errors from npmCmdExecutor.Run into user-facing messages.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errNpmNotFound) {
		return fmt.Errorf(
			"npm is not installed or not in PATH; install npm >= %s to scan this project: %w",
			minNpmVersion, err,
		)
	}

	if errors.Is(err, errNpmVersionTooLow) {
		return fmt.Errorf(
			"npm >= %s is required for dependency graph resolution: %w",
			minNpmVersion, err,
		)
	}

	return fmt.Errorf("running npm ls: %w", err)
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
		if !isLockfileName(filepath.Base(*options.Global.TargetFile)) {
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering npm lockfile: %w", err)
		}

		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithIncludes(lockfileNames...),
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
			return nil, fmt.Errorf("discovering npm lockfiles: %w", err)
		}

		return dedupeLockfilesPerDir(files), nil

	default:
		// Prefer npm-shrinkwrap.json over package-lock.json (matches npm CLI
		// behavior). Either is read by `npm ls --package-lock-only` identically.
		for _, name := range lockfileNames {
			candidate := filepath.Join(dir, name)
			if fileExists(candidate) {
				return []discovery.FindResult{{Path: candidate, RelPath: name}}, nil
			}
		}
		return nil, nil
	}
}

// dedupeLockfilesPerDir returns a slice where, for each directory containing
// both npm-shrinkwrap.json and package-lock.json, only the npm-shrinkwrap.json
// entry is kept. Matches npm CLI precedence so we don't run `npm ls` twice in
// the same dir and produce duplicate dep graphs.
func dedupeLockfilesPerDir(files []discovery.FindResult) []discovery.FindResult {
	byDir := make(map[string]discovery.FindResult, len(files))
	for _, f := range files {
		dir := filepath.Dir(f.Path)
		existing, seen := byDir[dir]
		if !seen {
			byDir[dir] = f
			continue
		}
		// Both lockfiles exist here. Keep the shrinkwrap entry.
		if filepath.Base(f.Path) == shrinkwrapFile {
			byDir[dir] = f
		} else if filepath.Base(existing.Path) != shrinkwrapFile {
			// Defensive: neither is shrinkwrap (shouldn't happen given our
			// include list, but keeps the map stable on unexpected input).
			byDir[dir] = existing
		}
	}
	out := make([]discovery.FindResult, 0, len(byDir))
	for _, f := range byDir {
		out = append(out, f)
	}
	return out
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// getExecutor returns the configured executor or the production npmCmdExecutor.
// Plugin{} zero-value is valid and uses the production executor by default.
func (p Plugin) getExecutor() npmLsRunner {
	if p.executor != nil {
		return p.executor
	}

	return &npmCmdExecutor{}
}
