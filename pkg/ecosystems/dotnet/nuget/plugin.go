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
	logFieldPackagesFolder  = "packagesFolder"
)

// Plugin implements ecosystems.SCAPlugin for .NET projects. It never runs
// `dotnet` or `nuget`: everything it needs is already on disk.
//
// Two kinds of project, resolved differently. SDK-style (PackageReference)
// projects come from the project.assets.json that `dotnet restore` leaves
// behind, which holds a fully resolved dependency set. packages.config projects
// hold no such thing, so they are resolved from the manifest plus the packages
// folder `nuget restore` populates beside it.
//
// A manifest it cannot resolve in full is left alone entirely — no result, no
// claimed file — so the legacy resolver still sees the project and behaves
// exactly as it does today. Reporting a partial result would be worse than
// reporting none: the file would be claimed, and the packages we failed to find
// would go unreported rather than being found by the resolver that follows.
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
	if options == nil {
		options = ecosystems.NewPluginOptions()
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
		if err := p.emitResults(ctx, log, file, options, onGraph); err != nil {
			return err
		}
	}

	return nil
}

// emitResults resolves one target file, dispatching on which manifest it is.
func (p Plugin) emitResults(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	options *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	if filepath.Base(file.Path) == projectAssetsFile {
		return p.emitAssetsResults(ctx, log, file, onGraph)
	}

	return p.emitFrameworkResult(ctx, log, file, options, onGraph)
}

// emitAssetsResults resolves an SDK-style project and emits a result per target
// framework. The results share a root name and target file, differing only in
// target runtime — which is how snyk-nuget-plugin distinguishes them.
//
// A framework that cannot be resolved is reported as a failure against its own
// runtime: the framework is named in the file, so the result is still
// identifiable. An assets file that cannot be read or parsed at all is logged
// and skipped, claiming nothing, so the legacy resolver still sees the project.
func (p Plugin) emitAssetsResults(
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

// rootTargetFiles returns the one manifest a single-project scan of dir
// resolves, or nothing when dir holds none.
//
// One, not all of them: a .NET project directory can hold more than one
// manifest — restore output in obj/ beside a copy at the root — and the CLI
// reports it as a single project, taking the first hit in DETECTABLE_FILES
// order. Returning every match would turn one project into several, since a
// scan without --all-projects still emits every result a plugin produces.
func rootTargetFiles(dir string) ([]discovery.FindResult, error) {
	// FindResult.Path is absolute. dir is frequently "." here, and a relative
	// path would leave the project with no directory to be named after.
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path for %s: %w", dir, err)
	}

	// Failing to read the scanned root is a setup failure rather than an absent
	// project, and is reported as one.
	rootNames, err := fileNamesIn(absDir)
	if err != nil {
		return nil, err
	}

	// obj/ is optional, and anything that stops it being read — absent, or not
	// a directory at all — means only that there is no restore output there.
	// The manifests beside it are still worth reporting.
	objNames, err := fileNamesIn(filepath.Join(absDir, objDir))
	if err != nil {
		objNames = nil
	}

	for _, candidate := range rootTargetFilePrecedence {
		names := rootNames
		if candidate.subdir != "" {
			names = objNames
		}

		if !names[candidate.name] {
			continue
		}

		relPath := filepath.Join(candidate.subdir, candidate.name)

		return []discovery.FindResult{{Path: filepath.Join(absDir, relPath), RelPath: relPath}}, nil
	}

	return nil, nil
}

// fileNamesIn lists the names of the regular files directly inside dir.
//
// Names are compared as the directory reports them rather than by stat-ing a
// path, so a case-insensitive filesystem does not quietly match
// Project.Assets.json where a case-sensitive one would not. Case-insensitive
// discovery is CMPA-715.
func fileNamesIn(dir string) (map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	names := make(map[string]bool, len(entries))

	for _, entry := range entries {
		if !entry.IsDir() {
			names[entry.Name()] = true
		}
	}

	return names, nil
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

// emitFrameworkResult resolves a packages.config project and emits its single
// result.
//
// One result, not one per framework: the manifest records no per-framework
// resolution, so there is one dependency set and one runtime to report it
// under. Anything that stops the project being resolved in full leaves it to
// the legacy resolver — see the note on Plugin.
func (p Plugin) emitFrameworkResult(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	options *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	targetFile := file.RelPath

	manifest, err := readPackagesConfig(file.Path, targetFile)
	if err != nil {
		return deferToLegacy(ctx, log, targetFile, err)
	}

	framework, ok, err := detectTargetFramework(filepath.Dir(file.Path), manifest)
	if err != nil {
		return deferToLegacy(ctx, log, targetFile, err)
	}

	// The target runtime is part of a project's identity, and nothing in this
	// manifest records the framework a package was resolved for. Guessing one
	// would report the project under a framework it does not target.
	if !ok {
		return deferToLegacy(ctx, log, targetFile, snykecosystems.NewNoTargetFrameworksFoundError(
			fmt.Sprintf("Could not determine a target framework for %s. "+
				"It needs a .csproj alongside it naming a TargetFramework, or targetFramework "+
				"attributes on its entries.", targetFile),
		))
	}

	packagesFolder := resolvePackagesFolder(file.Path, options.Dotnet.PackagesFolder)

	log.Debug(ctx, "Resolving .NET project",
		logger.Attr(logFieldTargetFile, targetFile),
		logger.Attr(logFieldTargetFramework, framework.original),
		logger.Attr(logFieldPackagesFolder, packagesFolder),
	)

	installed := installedPackages(ctx, log, manifest.packages, packagesFolder)

	children, err := nuspecChildren(installed, packagesFolder, framework)
	if err != nil {
		return deferToLegacy(ctx, log, targetFile, err)
	}

	rootName := rootComponentName(file)

	graph, err := buildFrameworkDepGraph(ctx, rootName, defaultVersion, installed, children)
	if err != nil {
		return deferToLegacy(ctx, log, targetFile, err)
	}

	result := p.newResult(targetFile, rootName, framework.original)
	result.DepGraph = graph

	return onGraph(result)
}

// deferToLegacy records why a project was left unresolved and reports nothing
// for it, so the workflow moves on to the legacy resolver. It never returns an
// error: one unresolvable project must not end a scan of many.
func deferToLegacy(ctx context.Context, log logger.Logger, targetFile string, err error) error {
	log.Error(ctx, "Leaving this .NET project to the legacy resolver",
		logger.Attr(logFieldTargetFile, targetFile), logger.Err(err))

	return nil
}
