package cargo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

const (
	PluginName    = "cargo"
	pkgManager    = "cargo"
	cargoTomlFile = "Cargo.toml"
	cargoLockFile = "Cargo.lock"

	logFieldLockFile = "lockFile"
)

// Plugin implements ecosystems.SCAPlugin for Cargo (Rust) projects.
// It runs `cargo tree --locked` to resolve the full dependency graph without
// bespoke Cargo.lock parsing, in line with the unified-scanners principle of
// preferring native package-manager tooling. The same command runs in CLI and
// SCM surfaces with no per-environment branching.
type Plugin struct {
	executor cargoTreeRunner
}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers Cargo.lock files under dir and produces a
// dep graph for each. Workspace expansion (one graph per member crate) lands
// in a later commit; today the plugin emits a single SCAResult per Cargo.lock.
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
		log.Debug(ctx, "No Cargo.lock files found", logger.Attr("dir", dir))
		return &ecosystems.PluginResult{}, nil
	}

	log.Debug(ctx, "Discovered Cargo.lock files", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	var results []ecosystems.SCAResult
	var processedFiles []string

	for _, file := range files {
		lockFileAbsDir := filepath.Dir(file.Path)

		fileResults := p.buildResults(ctx, log, file.RelPath, lockFileAbsDir, exec)
		for _, r := range fileResults {
			if r.Error != nil {
				log.Error(ctx, "Failed to build cargo dependency graph",
					logger.Attr(logFieldLockFile, file.RelPath),
					logger.Err(r.Error),
				)
			}
		}
		results = append(results, fileResults...)
		processedFiles = append(processedFiles, file.RelPath)
		for _, r := range fileResults {
			if tf := r.ProjectDescriptor.GetTargetFile(); tf != "" {
				processedFiles = append(processedFiles, tf)
			}
		}
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
	exec cargoTreeRunner,
) []ecosystems.SCAResult {
	// TargetFile for error results: the Cargo.toml alongside Cargo.lock.
	lockFileDir := filepath.Dir(lockFileRelPath)
	rootTargetFile := filepath.Join(lockFileDir, cargoTomlFile)

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

	log.Info(ctx, "Building cargo dependency graph", logger.Attr(logFieldLockFile, lockFileRelPath))

	output, err := exec.Run(ctx, lockFileAbsDir)
	if err != nil {
		return errResult(p.wrapRunError(err))
	}
	defer output.Close()

	out, err := parseTree(ctx, log, output)
	if err != nil {
		return errResult(fmt.Errorf("parsing cargo tree output: %w", err))
	}

	log.Debug(ctx, "Parsed cargo tree output",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr("packages", len(out.Graph)),
	)

	dg, err := buildDepGraph(out)
	if err != nil {
		return errResult(fmt.Errorf("building dep graph: %w", err))
	}

	log.Info(ctx, "Successfully built cargo dependency graph",
		logger.Attr(logFieldLockFile, lockFileRelPath),
	)

	tf := filepath.Join(lockFileDir, cargoTomlFile)

	return []ecosystems.SCAResult{{
		DepGraph: dg,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       pkgManager,
				TargetFile:        &tf,
				RootComponentName: dg.GetRootPkg().Info.Name,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			VersionBuildInfo:     map[string]string{},
			NormalisedTargetFile: tf,
		},
	}}
}

// wrapRunError converts errors from cargoTreeRunner.Run into user-facing messages.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errCargoNotFound) {
		return fmt.Errorf(
			"cargo is not installed or not in PATH; install the Rust toolchain to scan this project: %w",
			err,
		)
	}

	return fmt.Errorf("running cargo tree: %w", err)
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
		if filepath.Base(*options.Global.TargetFile) != cargoLockFile {
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering Cargo.lock files: %w", err)
		}

		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(cargoLockFile),
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
			return nil, fmt.Errorf("discovering Cargo.lock files: %w", err)
		}

		return files, nil

	default:
		// Check root directory only; return empty (not an error) if Cargo.lock is absent.
		rootLock := filepath.Join(dir, cargoLockFile)
		if !fileExists(rootLock) {
			return nil, nil
		}

		return []discovery.FindResult{{Path: rootLock, RelPath: cargoLockFile}}, nil
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// getExecutor returns the configured executor or the production cargoCmdExecutor.
// Plugin{} zero-value is valid and uses the production executor by default.
func (p Plugin) getExecutor() cargoTreeRunner {
	if p.executor != nil {
		return p.executor
	}

	return &cargoCmdExecutor{}
}
