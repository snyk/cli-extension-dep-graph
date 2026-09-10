package nuget

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	logFieldRootName        = "rootName"
)

// Plugin implements ecosystems.SCAPlugin for .NET projects. It never runs
// `dotnet` or `nuget`: everything it needs is already on disk.
//
// Two kinds of project, resolved differently. SDK-style (PackageReference)
// projects come from the project.assets.json that `dotnet restore` leaves
// behind, which holds a fully resolved dependency set. packages.config and
// project.json projects hold no such thing, so they are resolved from the
// manifest plus the packages folder `nuget restore` populates beside it.
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

	files, err := p.discoverTargetFiles(ctx, log, dir, options)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		log.Debug(ctx, "No .NET target files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered .NET target files", logger.Attr("count", len(files)))

	filter := &targetFrameworkFilter{requested: options.Dotnet.TargetFramework}

	for _, file := range files {
		if err := p.emitResults(ctx, log, file, options, filter, onGraph); err != nil {
			return err
		}
	}

	// A filter that matched nothing anywhere is a mistake in the flag rather
	// than a property of the repo, and saying so is the only way the user finds
	// out: every project it turned away reported nothing. Failing here is
	// deliberate — a scan that quietly tested no projects at all is worse than
	// one that stops.
	return filter.reportIfNothingMatched(ctx, log, p, onGraph)
}

// targetFrameworkFilter applies --dotnet-target-framework across one run. It
// remembers what it turned away so that a filter matching nothing can name the
// frameworks the scan did find.
type targetFrameworkFilter struct {
	requested string
	matched   int
	declined  []declinedProject
	found     []string
}

// declinedProject is a project the filter turned away, kept so the scan-level
// error can be attributed to a real project rather than to the directory.
type declinedProject struct {
	targetFile string
	rootName   string
}

// active reports whether a target framework was requested at all.
func (f *targetFrameworkFilter) active() bool { return f.requested != "" }

// keep reports whether a project declaring these frameworks is in scope,
// returning the one to resolve. Frameworks are the project's own, in the
// spelling it declared them.
func (f *targetFrameworkFilter) keep(file discovery.FindResult, frameworks []string) (string, bool) {
	selected, ok := selectTargetFramework(frameworks, f.requested)
	if !ok {
		f.declined = append(f.declined, declinedProject{
			targetFile: file.RelPath,
			rootName:   rootComponentName(file),
		})

		for _, framework := range frameworks {
			if !slices.Contains(f.found, framework) {
				f.found = append(f.found, framework)
			}
		}

		return "", false
	}

	f.matched++

	return selected, true
}

// reportIfNothingMatched emits one error result when the filter turned away
// every project it saw and kept none. Attributed to the first project it
// declined: there is no single file at fault, and the message names the whole
// scan rather than that project.
func (f *targetFrameworkFilter) reportIfNothingMatched(
	ctx context.Context,
	log logger.Logger,
	p Plugin,
	onGraph ecosystems.OnGraphFunc,
) error {
	if !f.active() || f.matched > 0 || len(f.declined) == 0 {
		return nil
	}

	log.Debug(ctx, "No .NET project declares the requested target framework",
		logger.Attr(logFieldTargetFramework, f.requested),
		logger.Attr("declinedProjects", len(f.declined)),
	)

	attributed := f.declined[0]

	err := snykecosystems.NewUnsupportedTargetFrameworkError(fmt.Sprintf(
		"No .NET project matched target framework %s. The %d .NET project(s) found declare: %s.",
		f.requested, len(f.declined), strings.Join(f.found, ", ")))

	return onGraph(p.errResult(attributed.targetFile, attributed.rootName, f.requested, err))
}

// emitResults resolves one target file, dispatching on which manifest it is.
func (p Plugin) emitResults(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	options *ecosystems.SCAPluginOptions,
	filter *targetFrameworkFilter,
	onGraph ecosystems.OnGraphFunc,
) error {
	if filepath.Base(file.Path) == projectAssetsFile {
		return p.emitAssetsResults(ctx, log, file, options, filter, onGraph)
	}

	return p.emitFrameworkResult(ctx, log, file, options, filter, onGraph)
}

// emitAssetsResults resolves an SDK-style project and emits a result per target
// framework it reports on — every framework the project declares, or the single
// one --dotnet-target-framework asked for. The results share a root name and
// target file, differing only in target runtime — which is how
// snyk-nuget-plugin distinguishes them.
//
// A framework that cannot be resolved is reported as a failure against its own
// runtime: the framework is named in the file, so the result is still
// identifiable. An assets file that cannot be read or parsed at all is logged
// and skipped, claiming nothing, so the legacy resolver still sees the project.
func (p Plugin) emitAssetsResults(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	options *ecosystems.SCAPluginOptions,
	filter *targetFrameworkFilter,
	onGraph ecosystems.OnGraphFunc,
) error {
	targetFile := file.RelPath

	// The assets file is what the dependencies are read from, and what messages
	// about them name, but it is restore output under obj/ rather than the
	// project itself. Identity names the project file instead, which is what the
	// legacy resolver reports an SDK-style project under — so a result and the
	// one it replaces name the same project.
	projectFile := projectFileOf(file)
	if projectFile == "" {
		projectFile = targetFile
	}
	claimed := claimedFiles(projectFile, targetFile)

	assets, err := readProjectAssets(file.Path, targetFile)
	if err != nil {
		log.Error(ctx, "Leaving this .NET project to the legacy resolver: its assets file could not be used",
			logger.Attr(logFieldTargetFile, targetFile), logger.Err(err))

		return nil
	}

	rootName := rootComponentName(file)
	if options.Dotnet.AssetsProjectName {
		if named := assets.Project.Restore.ProjectName; named != "" {
			rootName = named
		} else {
			// Silently keeping the derived name would look like the flag did
			// nothing.
			log.Debug(ctx, "The restore recorded no project name, so the .NET project keeps its directory-derived name",
				logger.Attr(logFieldTargetFile, targetFile), logger.Attr(logFieldRootName, rootName))
		}
	}

	frameworks := assets.targetFrameworks()

	if filter.active() {
		selected, ok := filter.keep(file, frameworks)
		if !ok {
			// Out of scope rather than broken, so nothing is reported for it —
			// a project that targets something else is not a failure. The file
			// is still claimed, so the legacy resolver cannot answer with a
			// framework this scan excluded, and the exclude set stays the same
			// whether or not the flag was passed.
			log.Debug(ctx, "Leaving out a .NET project that does not declare the requested target framework",
				logger.Attr(logFieldTargetFile, targetFile),
				logger.Attr(logFieldTargetFramework, filter.requested),
			)

			return onGraph(p.claimOnlyResult(targetFile))
		}

		frameworks = []string{selected}
	}

	for _, framework := range frameworks {
		targetsKey := assets.matchTargetsKey(framework)
		if targetsKey == "" {
			// Guessing a sibling's packages would report the wrong dependencies
			// under this framework's name.
			err := snykecosystems.NewUnsupportedTargetFrameworkError(
				fmt.Sprintf("No resolved packages for target framework %s in %s.", framework, targetFile),
			)

			if err := onGraph(p.errResult(projectFile, claimed, rootName, framework, err)); err != nil {
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
			if err := onGraph(p.errResult(projectFile, claimed, rootName, framework, buildErr)); err != nil {
				return err
			}

			continue
		}

		result := p.newResult(projectFile, claimed, rootName, framework)
		result.DepGraph = graph

		if err := onGraph(result); err != nil {
			return err
		}
	}

	return nil
}

// newResult assembles the descriptor and metadata every result carries.
// claimed stops the legacy resolver reporting the same project again — the
// workflow turns claimed files into --exclude-paths for the plugins that follow.
func (p Plugin) newResult(targetFile string, claimed []string, rootName, targetRuntime string) ecosystems.SCAResult {
	return ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: newProjectIdentity(targetFile, targetRuntime, rootName),
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: targetFile,
		},
		ProcessedFiles: claimed,
	}
}

// errResult reports a framework the resolver could not build a graph for. The
// runtime is still set: it is what identifies the framework we failed on.
func (p Plugin) errResult(targetFile string, claimed []string, rootName, targetRuntime string, err error) ecosystems.SCAResult {
	result := p.newResult(targetFile, claimed, rootName, targetRuntime)
	result.DepGraph = nil
	result.Error = err

	return result
}

// claimOnlyResult claims a target file without reporting anything for it: the
// project was recognized and deliberately left out of scope. It carries no
// identity, because a project left out has no target runtime to be identified
// by, and none is needed — the claim is by path.
func (p Plugin) claimOnlyResult(targetFile string) ecosystems.SCAResult {
	return ecosystems.SCAResult{
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: targetFile,
		},
		ProcessedFiles: []string{targetFile},
	}
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
// file, stepping over obj/. Derived from the absolute path so a target file in
// the scanned root still yields a real name.
func rootComponentName(file discovery.FindResult) string {
	return filepath.Base(projectDirOf(file.Path))
}

// projectDirOf returns the directory of the project path belongs to, stepping
// over obj/ (case-insensitively, as snyk-nuget-plugin does) for a restore output
// written there.
func projectDirOf(path string) string {
	dir := filepath.Dir(path)
	if strings.EqualFold(filepath.Base(dir), objDir) {
		return filepath.Dir(dir)
	}

	return dir
}

// projectFileOf returns the project file naming the project, relative to the
// scanned root, or "" when there is none beside it or the directory could not be
// read. Callers fall back to the manifest they were resolving.
func projectFileOf(file discovery.FindResult) string {
	projectFile, found, err := firstProjectFile(projectDirOf(file.Path))
	if err != nil || !found {
		return ""
	}

	return filepath.Join(projectDirOf(file.RelPath), filepath.Base(projectFile))
}

// claimedFiles are the files a result claims so the legacy resolver does not
// report the same project a second time.
//
// The project file leads: a claim only excludes the path it names, and an
// SDK-style project is reported under its project file, so claiming the assets
// file alone would exclude nothing. The manifest is claimed alongside it because
// a project resolved from packages.config or project.json is reported under that
// file instead.
func claimedFiles(projectFile, targetFile string) []string {
	if projectFile == "" || projectFile == targetFile {
		return []string{targetFile}
	}

	return []string{projectFile, targetFile}
}

// discoverTargetFiles honors the same three request shapes as the other
// resolvers: an explicit --file, an --all-projects scan, or the scanned root.
func (p Plugin) discoverTargetFiles(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	switch {
	case options.Global.TargetFile != nil:
		if !isSupportedTargetFile(*options.Global.TargetFile) {
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, log, dir, discovery.WithTargetFile(*options.Global.TargetFile))
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
			discovery.WithMaxDepth(options.Global.DetectionDepth),
		}

		if len(options.Global.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
		}
		if len(options.Global.ExcludePaths) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.ExcludePaths...))
		}

		files, err := discovery.FindFiles(ctx, log, dir, findOpts...)
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
// One, not all of them: a .NET project directory routinely holds several
// manifests — snyk/cli's own nuget-app fixture has packages.config,
// project.json and project.assets.json side by side — and the CLI reports it as
// a single project, taking the first hit in DETECTABLE_FILES order. Returning
// every match would turn one project into three, since a scan without
// --all-projects still emits every result a plugin produces.
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
// Packages.config where a case-sensitive one would not. Case-insensitive
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

// emitFrameworkResult resolves a packages.config or project.json project and
// emits its single result.
//
// One result, not one per framework: these manifests record no per-framework
// resolution, so there is one dependency set and one runtime to report it
// under. Anything that stops the project being resolved in full leaves it to
// the legacy resolver — see the note on Plugin.
func (p Plugin) emitFrameworkResult(
	ctx context.Context,
	log logger.Logger,
	file discovery.FindResult,
	options *ecosystems.SCAPluginOptions,
	filter *targetFrameworkFilter,
	onGraph ecosystems.OnGraphFunc,
) error {
	targetFile := file.RelPath

	manifest, err := readFrameworkManifest(file.Path, targetFile)
	if err != nil {
		return deferToLegacy(ctx, log, targetFile, err)
	}

	framework, ok, err := detectTargetFramework(filepath.Dir(file.Path), manifest)
	if err != nil {
		return deferToLegacy(ctx, log, targetFile, err)
	}

	// The target runtime is part of a project's identity, and nothing in these
	// manifests records the framework a package was resolved for. Guessing one
	// would misreport which .nuspec dependency groups apply.
	if !ok {
		return deferToLegacy(ctx, log, targetFile, snykecosystems.NewNoTargetFrameworksFoundError(
			fmt.Sprintf("Could not determine a target framework for %s. "+
				"It needs a .csproj alongside it naming a TargetFramework, or, for a packages.config, "+
				"targetFramework attributes on its entries.", targetFile),
		))
	}

	// These manifests resolve one dependency set rather than one per framework,
	// but they still have exactly one — detectTargetFramework just named it —
	// so --dotnet-target-framework applies here too. Ignoring it would report a
	// .NET Framework project under a framework the user filtered out.
	if filter.active() {
		if _, ok := filter.keep(file, []string{framework.original}); !ok {
			log.Debug(ctx, "Leaving out a .NET project that does not declare the requested target framework",
				logger.Attr(logFieldTargetFile, targetFile),
				logger.Attr(logFieldTargetFramework, filter.requested),
			)

			return onGraph(p.claimOnlyResult(targetFile))
		}
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

	rootName := manifest.rootName
	if rootName == "" {
		rootName = rootComponentName(file)
	}

	rootVersion := manifest.rootVersion
	if rootVersion == "" {
		rootVersion = defaultVersion
	}

	graph, err := buildFrameworkDepGraph(ctx, rootName, rootVersion, installed, children)
	if err != nil {
		return deferToLegacy(ctx, log, targetFile, err)
	}

	result := p.newResult(targetFile, claimedFiles(projectFileOf(file), targetFile), rootName, framework.original)
	result.DepGraph = graph

	return onGraph(result)
}

// readFrameworkManifest reads whichever of the two older manifests this is.
// Only the three names in targetFileNames reach here, and emitResults has
// already taken project.assets.json.
func readFrameworkManifest(path, displayPath string) (*frameworkManifest, error) {
	if filepath.Base(path) == packagesConfigFile {
		return readPackagesConfig(path, displayPath)
	}

	return readProjectJSON(path, displayPath)
}

// deferToLegacy records why a project was left unresolved and reports nothing
// for it, so the workflow moves on to the legacy resolver. It never returns an
// error: one unresolvable project must not end a scan of many.
//
// A file that turned out to belong to another ecosystem is logged at debug
// rather than error. project.json is a common enough name that an Nx workspace
// has one per package, and discovery matches every one of them — reporting each
// as an error would bury the .NET projects that really did fail.
func deferToLegacy(ctx context.Context, log logger.Logger, targetFile string, err error) error {
	if errors.Is(err, errNotDotnetManifest) {
		log.Debug(ctx, "Not a .NET project",
			logger.Attr(logFieldTargetFile, targetFile), logger.Err(err))

		return nil
	}

	log.Error(ctx, "Leaving this .NET project to the legacy resolver",
		logger.Attr(logFieldTargetFile, targetFile), logger.Err(err))

	return nil
}
