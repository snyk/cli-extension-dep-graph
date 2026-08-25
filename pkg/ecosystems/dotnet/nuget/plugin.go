package nuget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const (
	// PluginName is "dotnet" to match the in-cluster resolver ecosystem key,
	// while the dep graphs report the "nuget" package manager (see pkgManager).
	PluginName = "dotnet"

	logFieldTargetFile      = "targetFile"
	logFieldTargetFramework = "targetFramework"
	logFieldTargetsKey      = "targetsKey"
)

// Plugin implements ecosystems.SCAPlugin for .NET projects, resolving SDK-style
// (PackageReference) projects from the project.assets.json that `dotnet restore`
// leaves behind. It never runs `dotnet`: the assets file already holds the
// resolved dependency set.
//
// Only project.assets.json is claimed. packages.config and project.json carry no
// resolved dependency set, so this plugin reports nothing for them and the
// workflow moves on to the legacy resolver.
type Plugin struct{}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers .NET target files under dir and emits one dep
// graph per target framework of each. Finding none is not an error: reporting
// nothing is how a plugin says "not my project".
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

	files, err := p.discoverTargetFiles(ctx, dir, options)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		log.Debug(ctx, "No .NET target files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered .NET target files", logger.Attr("count", len(files)))

	for _, file := range files {
		if err := p.emitResults(ctx, log, file, onGraph); err != nil {
			return err
		}
	}

	return nil
}

// emitResults resolves one target file and emits a result per target framework.
// The results share a root name and target file, differing only in target
// runtime — which is how snyk-nuget-plugin distinguishes them.
//
// A framework that cannot be resolved is reported as a failure against its own
// runtime. An assets file that cannot be read or parsed at all is logged and
// skipped, claiming nothing, so the legacy resolver still sees the project: it
// reaches .NET projects through `dotnet` and can resolve some this one cannot.
func (p Plugin) emitResults(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	onGraph ecosystems.OnGraphFunc,
) error {
	targetFile := file.RelPath
	rootName := rootComponentName(file)

	assets, err := readProjectAssets(file.Path, targetFile)
	if err != nil {
		log.Error(ctx, "Leaving this .NET project to the legacy resolver: its assets file could not be used",
			logger.Attr(logFieldTargetFile, targetFile), logger.Err(err))

		return nil
	}

	for _, framework := range assets.targetFrameworks() {
		targetsKey := assets.matchTargetsKey(framework)
		if targetsKey == "" {
			// Guessing a sibling's packages would report the wrong dependencies
			// under this framework's name.
			err := snykecosystems.NewUnsupportedTargetFrameworkError(
				fmt.Sprintf("No resolved packages for target framework %s in %s.", framework, targetFile),
			)

			if err := onGraph(p.errResult(targetFile, rootName, framework, err)); err != nil {
				return err
			}

			continue
		}

		log.Debug(ctx, "Resolving .NET target framework",
			logger.Attr(logFieldTargetFile, targetFile),
			logger.Attr(logFieldTargetFramework, framework),
			logger.Attr(logFieldTargetsKey, targetsKey),
		)

		graph, buildErr := buildDepGraph(ctx, assets, rootName, targetsKey)
		if buildErr != nil {
			if err := onGraph(p.errResult(targetFile, rootName, framework, buildErr)); err != nil {
				return err
			}

			continue
		}

		result := p.newResult(targetFile, rootName, framework)
		result.DepGraph = graph

		if err := onGraph(result); err != nil {
			return err
		}
	}

	return nil
}

// newResult assembles the descriptor and metadata every result carries.
// ProcessedFiles claims the assets file, which stops the legacy resolver
// reporting the same project again — the workflow turns claimed files into
// --exclude-paths for the plugins that follow.
func (p Plugin) newResult(targetFile, rootName, targetRuntime string) ecosystems.SCAResult {
	return ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: newProjectIdentity(targetFile, targetRuntime, rootName),
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: targetFile,
		},
		ProcessedFiles: []string{targetFile},
	}
}

// errResult reports a framework the resolver could not build a graph for. The
// runtime is still set: it is what identifies the framework we failed on.
func (p Plugin) errResult(targetFile, rootName, targetRuntime string, err error) ecosystems.SCAResult {
	result := p.newResult(targetFile, rootName, targetRuntime)
	result.DepGraph = nil
	result.Error = err

	return result
}

// newProjectIdentity builds the identity for one .NET project. targetRuntime is
// a required parameter because it is part of a project's identity — it is what
// tells a multi-targeting project's graphs apart. Promoting this to
// pkg/identity is CMPA-721.
func newProjectIdentity(targetFile, targetRuntime, rootComponentName string) identity.ProjectIdentity {
	return identity.ProjectIdentity{
		ProjectType:       pkgManager,
		TargetFile:        &targetFile,
		TargetRuntime:     &targetRuntime,
		RootComponentName: rootComponentName,
	}
}

// rootComponentName names the project after the directory containing its target
// file, stepping over obj/ (case-insensitively, as snyk-nuget-plugin does).
// Derived from the absolute path so a target file in the scanned root still
// yields a real name.
func rootComponentName(file discovery.FindResult) string {
	dir := filepath.Dir(file.Path)
	if strings.EqualFold(filepath.Base(dir), objDir) {
		dir = filepath.Dir(dir)
	}

	return filepath.Base(dir)
}

// discoverTargetFiles honors the same three request shapes as the other
// resolvers: an explicit --file, an --all-projects scan, or the scanned root.
func (p Plugin) discoverTargetFiles(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	if options == nil {
		options = ecosystems.NewPluginOptions()
	}

	switch {
	case options.Global.TargetFile != nil:
		if !isSupportedTargetFile(*options.Global.TargetFile) {
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering .NET target files: %w", err)
		}

		return files, nil

	case options.Global.AllProjects:
		// WithCommonExcludes matches the CLI's own ignoreFolders. It does not
		// prune obj/ or bin/, so obj/project.assets.json stays discoverable.
		findOpts := []discovery.FindOption{
			discovery.WithIncludes(targetFileNames...),
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
			return nil, fmt.Errorf("discovering .NET target files: %w", err)
		}

		return files, nil

	default:
		// Check the root directory only; return empty (not an error) when it
		// holds no .NET target file.
		return rootTargetFiles(dir)
	}
}

// rootTargetFiles lists the target files for a single project rooted at dir.
// obj/ is the one subdirectory it looks into: restore writes
// project.assets.json there, and detect.ts allows exactly that path.
func rootTargetFiles(dir string) ([]discovery.FindResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	// FindResult.Path is absolute. dir is frequently "." here, and a relative
	// path would leave the project with no directory to be named after.
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path for %s: %w", dir, err)
	}

	var files []discovery.FindResult

	for _, entry := range entries {
		if entry.IsDir() || !isSupportedTargetFile(entry.Name()) {
			continue
		}

		files = append(files, discovery.FindResult{
			Path:    filepath.Join(absDir, entry.Name()),
			RelPath: entry.Name(),
		})
	}

	if objAssets := filepath.Join(absDir, objDir, projectAssetsFile); fileExists(objAssets) {
		files = append(files, discovery.FindResult{
			Path:    objAssets,
			RelPath: filepath.Join(objDir, projectAssetsFile),
		})
	}

	return files, nil
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// isSupportedTargetFile reports whether path's base name is one this plugin
// recognizes, matching how discovery applies its include patterns — so
// --file=obj/project.assets.json is accepted.
func isSupportedTargetFile(path string) bool {
	base := filepath.Base(path)

	for _, name := range targetFileNames {
		if base == name {
			return true
		}
	}

	return false
}
