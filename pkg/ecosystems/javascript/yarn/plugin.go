package yarn

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
	PluginName       = "yarn"
	logFieldLockFile = "lockFile"
)

// Plugin implements ecosystems.SCAPlugin for Yarn projects. It supports both
// Yarn Classic (v1.x) and Berry (v2/3/4) by shelling out to the user's
// installed yarn and parsing its output — no `yarn install`, no node_modules,
// no project-dir mutation.
type Plugin struct {
	executor yarnRunner
}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers yarn.lock files under dir and produces dep
// graphs for each one. Workspace projects yield one SCAResult per workspace
// package plus one for the root; non-workspace projects yield a single result.
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
		log.Debug(ctx, "No yarn.lock files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered yarn.lock files", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	for _, file := range files {
		lockFileAbsDir := filepath.Dir(file.Path)

		fileResults := p.buildResults(ctx, log, file.RelPath, lockFileAbsDir, exec)
		for i := range fileResults {
			r := &fileResults[i]
			if r.Error != nil {
				log.Error(ctx, "Failed to build yarn dependency graph",
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
	exec yarnRunner,
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

	log.Info(ctx, "Building yarn dependency graph", logger.Attr(logFieldLockFile, lockFileRelPath))

	pkgJSON, err := readPackageJSON(lockFileAbsDir)
	if err != nil {
		return errResult(fmt.Errorf("reading package.json: %w", err))
	}
	if pkgJSON.Name == "" {
		return errResult(fmt.Errorf(`package.json is missing a "name" field; yarn dep graph requires a named root package`))
	}

	runResult, err := exec.Run(ctx, lockFileAbsDir)
	if err != nil {
		return errResult(p.wrapRunError(err))
	}
	defer runResult.Output.Close()

	var parsed *parsedOutput
	switch runResult.Family {
	case familyClassic:
		parsed, err = parseYarnListOutput(ctx, log, runResult.Output, pkgJSON, lockFileAbsDir)
	case familyBerry:
		parsed, err = parseYarnInfoOutput(ctx, log, runResult.Output, pkgJSON)
	default:
		return errResult(fmt.Errorf("unsupported yarn family"))
	}
	if err != nil {
		return errResult(fmt.Errorf("parsing yarn output: %w", err))
	}

	log.Debug(ctx, "Parsed yarn output",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr("packages", len(parsed.Graph)),
	)

	graphResults, err := buildDepGraphs(pkgJSON.Name, pkgJSON.Version, parsed)
	if err != nil {
		return errResult(fmt.Errorf("building dep graphs: %w", err))
	}

	log.Info(ctx, "Successfully built yarn dependency graphs",
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
				VersionBuildInfo:     map[string]string{"yarn": runResult.Version},
				NormalisedTargetFile: tf,
			},
		}
	}
	return results
}

// wrapRunError converts errors from the executor into user-facing messages.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errYarnNotFound) {
		return fmt.Errorf(
			"yarn is not installed or not in PATH; install yarn (v1 or v2+) to scan this project: %w",
			err,
		)
	}
	if errors.Is(err, errYarnVersionUnsupported) {
		return fmt.Errorf("yarn version not supported: %w", err)
	}
	return fmt.Errorf("running yarn: %w", err)
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
		if filepath.Base(*options.Global.TargetFile) != yarnLockFile {
			return nil, nil
		}
		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering yarn.lock files: %w", err)
		}
		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(yarnLockFile),
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
			return nil, fmt.Errorf("discovering yarn.lock files: %w", err)
		}
		return files, nil

	default:
		rootLock := filepath.Join(dir, yarnLockFile)
		if !fileExists(rootLock) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: rootLock, RelPath: yarnLockFile}}, nil
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// getExecutor returns the configured executor or the production yarnCmdExecutor.
// Plugin{} zero-value is valid and uses the production executor by default.
func (p Plugin) getExecutor() yarnRunner {
	if p.executor != nil {
		return p.executor
	}
	return &yarnCmdExecutor{}
}
