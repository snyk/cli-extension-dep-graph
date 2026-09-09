package nuget

import (
	"context"
	"errors"
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
	logFieldProjectPath     = "projectPath"

	// Reported when a solution is handed back to the legacy resolver. Asserted on
	// in tests, so they stay tied to what a user would see in a debug log.
	msgSolutionUnreadable   = "Leaving this solution to the legacy resolver: it could not be read"
	msgSolutionUnrestored   = "Leaving this solution to the legacy resolver: a project in it has no assets file"
	msgSolutionUnresolvable = "Leaving this solution to the legacy resolver: a project in it could not be resolved"
	msgSolutionEscapesScan  = "Leaving this solution to the legacy resolver: it references a project outside the scanned directory"
	msgSolutionHoldsNothing = "Solution holds no projects"
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

	files, fromSolution, err := p.discoverTargetFiles(ctx, log, dir, options)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		log.Debug(ctx, "No .NET target files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered .NET target files", logger.Attr("count", len(files)))

	if fromSolution {
		return p.emitSolutionResults(ctx, log, files, options, onGraph)
	}

	for _, file := range files {
		if err := p.emitResults(ctx, log, file, options, onGraph); err != nil {
			return err
		}
	}

	return nil
}

// emitSolutionResults resolves every project a solution holds, emitting nothing
// unless all of them produced a result.
//
// The all-or-nothing rule cannot be enforced when the target files are chosen:
// an assets file that exists can still turn out to be unreadable, or to declare
// no framework we can resolve, and `emitResults` reports nothing for it. Emitting
// the projects that did work would leave the rest reported by *nobody* — the
// workflow stops after the first resolver that reports anything unless
// --all-projects is set, so the legacy resolver would never see them. Buffering
// until the last project is in is what keeps "claims all of it or none of it"
// true rather than merely intended.
func (p Plugin) emitSolutionResults(
	ctx context.Context,
	log logger.Logger,
	files []discovery.FindResult,
	options *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	buffered := make([]ecosystems.SCAResult, 0, len(files))

	for _, file := range files {
		before := len(buffered)

		err := p.emitResults(ctx, log, file, options, func(result ecosystems.SCAResult) error {
			buffered = append(buffered, result)
			return nil
		})
		if err != nil {
			return err
		}

		if len(buffered) == before {
			log.Debug(ctx, msgSolutionUnresolvable,
				logger.Attr(logFieldTargetFile, file.RelPath))

			return nil
		}
	}

	for i := range buffered {
		if err := onGraph(buffered[i]); err != nil {
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
//
// The second return value reports whether the target files came from a solution,
// which is what makes them all-or-nothing to claim.
func (p Plugin) discoverTargetFiles(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, bool, error) {
	switch {
	case options.Global.TargetFile != nil:
		if isSlnxFile(*options.Global.TargetFile) {
			files, err := solutionTargetFiles(ctx, log, dir, *options.Global.TargetFile)
			return files, true, err
		}

		if !isSupportedTargetFile(*options.Global.TargetFile) {
			return nil, false, nil
		}

		files, err := discovery.FindFiles(ctx, log, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, false, fmt.Errorf("discovering .NET target files: %w", err)
		}

		return files, false, nil

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

		files, err := discovery.FindFiles(ctx, log, dir, findOpts...)
		if err != nil {
			return nil, false, fmt.Errorf("discovering .NET target files: %w", err)
		}

		return files, false, nil

	default:
		// Check the root directory only; return empty (not an error) when it
		// holds no .NET target file.
		files, err := rootTargetFiles(dir)
		return files, false, err
	}
}

// solutionTargetFiles expands a `.slnx` solution passed to --file into the
// assets file of each project it holds. A solution is a target selector rather
// than a manifest: `--file=App.slnx` means "the projects App.slnx holds", which
// is how the CLI has always treated `--file=App.sln`.
//
// Only restore output is expanded: a project is taken to be the
// obj/project.assets.json beside it. The manifests this plugin resolves without
// restore output — packages.config and project.json — are not reached through a
// solution, because a solution names projects rather than manifests and nothing
// in it says which manifest a project carries.
//
// It is all or nothing. If any project in the solution has no
// project.assets.json to read, this resolver claims none of them and the legacy
// resolver takes the whole solution — it reaches projects this path does not,
// including ones it can restore itself. Claiming only the projects we can
// resolve would silently drop the rest, because the workflow stops after the
// first resolver that reports anything unless --all-projects is set. The rest of
// that rule is enforced in emitSolutionResults, which is where an
// existing-but-unusable assets file surfaces.
//
// A solution can reference a project anywhere on disk, including outside the
// directory being scanned. Every other resolver discovers its target files by
// walking down from that directory, so a target file's path relative to it has
// always been inside it — and that relative path becomes the project's identity.
// Rather than mint a new `../`-shaped identity here, a solution that reaches
// outside the scan goes to the legacy resolver, which re-roots each project
// before any manifest plugin sees it.
func solutionTargetFiles(
	ctx context.Context,
	log logger.Logger,
	dir string,
	solutionFile string,
) ([]discovery.FindResult, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving absolute path for %s: %w", dir, err)
	}

	solutionPath := solutionFile
	if !filepath.IsAbs(solutionPath) {
		solutionPath = filepath.Join(absDir, solutionPath)
	}

	projectPaths, err := parseSlnx(solutionPath)
	if err != nil {
		log.Error(ctx, msgSolutionUnreadable,
			logger.Attr(logFieldTargetFile, solutionFile), logger.Err(err))

		return nil, nil
	}

	solutionDir := filepath.Dir(solutionPath)
	files := make([]discovery.FindResult, 0, len(projectPaths))
	// A hand-edited or badly merged solution can name the same project twice, or
	// name two projects that share a directory. Both resolve to one assets file,
	// and reporting it once per mention would submit the same project repeatedly.
	claimed := make(map[string]struct{}, len(projectPaths))

	for _, projectPath := range projectPaths {
		assetsPath := filepath.Join(
			solutionProjectDir(solutionDir, projectPath), objDir, projectAssetsFile,
		)

		if !fileExists(assetsPath) {
			log.Debug(ctx, msgSolutionUnrestored,
				logger.Attr(logFieldTargetFile, solutionFile),
				logger.Attr(logFieldProjectPath, projectPath))

			return nil, nil
		}

		relPath, relErr := filepath.Rel(absDir, assetsPath)
		if relErr != nil || escapesDir(relPath) {
			log.Debug(ctx, msgSolutionEscapesScan,
				logger.Attr(logFieldTargetFile, solutionFile),
				logger.Attr(logFieldProjectPath, projectPath))

			// Not an error to report: a project we cannot name relative to the
			// scan is one we hand to the legacy resolver, which re-roots each
			// project itself. Claiming nothing is how that handover happens.
			return nil, nil //nolint:nilerr // deliberate handover, see above
		}

		if _, seen := claimed[assetsPath]; seen {
			continue
		}
		claimed[assetsPath] = struct{}{}

		files = append(files, discovery.FindResult{Path: assetsPath, RelPath: relPath})
	}

	if len(files) == 0 {
		log.Debug(ctx, msgSolutionHoldsNothing,
			logger.Attr(logFieldTargetFile, solutionFile))
	}

	return files, nil
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

// escapesDir reports whether a path relative to the scanned directory points
// outside it.
func escapesDir(relPath string) bool {
	return relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator))
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

	result := p.newResult(targetFile, rootName, framework.original)
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
