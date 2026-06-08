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

	files, err := p.discoverLockFiles(ctx, dir, options)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		log.Debug(ctx, "No package-lock.json files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered package-lock.json files", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	for _, file := range files {
		lockFileAbsDir := filepath.Dir(file.Path)

		fileResults := p.buildResults(ctx, log, file.RelPath, lockFileAbsDir, exec)
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

	output, err := exec.Run(ctx, lockFileAbsDir)
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

	workspacePaths := readWorkspacePaths(lockFileAbsDir)

	graphResults, err := buildDepGraphs(rootName, rootVersion, parsed, workspacePaths)
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
		if filepath.Base(*options.Global.TargetFile) != packageLockFile {
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering package-lock.json files: %w", err)
		}

		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(packageLockFile),
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
			return nil, fmt.Errorf("discovering package-lock.json files: %w", err)
		}

		return files, nil

	default:
		rootLock := filepath.Join(dir, packageLockFile)
		if !fileExists(rootLock) {
			return nil, nil
		}

		return []discovery.FindResult{{Path: rootLock, RelPath: packageLockFile}}, nil
	}
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
