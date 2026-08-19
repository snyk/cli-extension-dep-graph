package nuget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const (
	// PluginName is "dotnet" rather than "nuget" to match the resolver
	// ecosystem key used in-cluster, while the dep graphs themselves report
	// the "nuget" package manager (see pkgManager).
	PluginName = "dotnet"

	logFieldTargetFile = "targetFile"
)

// Plugin implements ecosystems.SCAPlugin for .NET projects.
//
// It is currently a placeholder: it discovers .NET target files and emits one
// empty dep graph per target file, logging that no resolution took place.
// Driving `dotnet restore` and building real graphs comes later; landing the
// plugin first lets the feature flag, registration, and end-to-end result
// handling be exercised against a known-empty result.
//
// Because no dependencies are resolved, the plugin deliberately does not claim
// its target files via SCAResult.ProcessedFiles, so the legacy resolver still
// scans them and reports real results alongside the empty graphs. Note this
// only holds for an --all-projects scan: consumers that stop at the first
// resolver to return anything (as the CLI's dep-graph workflow does for a
// single project) see the empty graph instead of the legacy result.
type Plugin struct{}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers .NET target files under dir and emits one
// empty dep graph per target file, each via onGraph as soon as it's built.
//
// Finding no .NET target files is not an error: the plugin reports nothing and
// returns nil, which is how a plugin says "not my project".
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
		if err := onGraph(p.buildResult(ctx, log, file)); err != nil {
			return err
		}
	}

	return nil
}

// buildResult produces the placeholder SCAResult for a single target file.
func (p Plugin) buildResult(ctx context.Context, log logger.Logger, file discovery.FindResult) ecosystems.SCAResult {
	log.Info(ctx, "WARNING: dotnet resolver is not yet implemented; returning an empty dep-graph",
		logger.Attr(logFieldTargetFile, file.RelPath),
	)

	targetFile := file.RelPath
	rootName := rootComponentName(file)

	descriptor := identity.ProjectDescriptor{
		Identity: newProjectIdentity(targetFile, placeholderTargetRuntime, rootName),
	}
	meta := &ecosystems.ResolverMetadata{
		PluginName:           PluginName,
		NormalisedTargetFile: targetFile,
	}

	graph, err := buildEmptyDepGraph(rootName, defaultVersion)
	if err != nil {
		return ecosystems.SCAResult{
			ProjectDescriptor: descriptor,
			ResolverMetadata:  meta,
			Error:             err,
		}
	}

	return ecosystems.SCAResult{
		DepGraph:          graph,
		ProjectDescriptor: descriptor,
		ResolverMetadata:  meta,
	}
}

// newProjectIdentity builds the identity for one .NET project.
//
// targetRuntime is a required parameter rather than a field left to the
// caller: every .NET result carries a target framework, so a constructor that
// cannot be called without one keeps it from being quietly dropped as this
// package grows. Promoting this to a shared helper in pkg/identity, so the
// other ecosystems get the same treatment, is worth doing separately.
func newProjectIdentity(targetFile, targetRuntime, rootComponentName string) identity.ProjectIdentity {
	return identity.ProjectIdentity{
		ProjectType:       pkgManager,
		TargetFile:        &targetFile,
		TargetRuntime:     &targetRuntime,
		RootComponentName: rootComponentName,
	}
}

// rootComponentName derives a root package name from a target file.
//
// Every recognized target file is a fixed name, so the containing directory
// names the project — stepping over obj/ when the target file sits in it, as
// getRootName does in snyk-nuget-plugin (lib/nuget-parser/index.ts:86-91).
// The comparison is case-insensitive there, so it is here too.
//
// Derived from the absolute path so that a target file in the scanned root
// (where RelPath's directory is ".") still yields a real name.
func rootComponentName(file discovery.FindResult) string {
	dir := filepath.Dir(file.Path)
	if strings.EqualFold(filepath.Base(dir), objDir) {
		dir = filepath.Dir(dir)
	}

	return filepath.Base(dir)
}

// discoverTargetFiles finds the .NET target files to report on, honoring the
// same three request shapes as the other resolvers: an explicit --file, a
// full --all-projects scan, or the scanned root directory only.
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
		// WithCommonExcludes is [".build", "node_modules"], which matches the
		// CLI's own ignoreFolders (src/lib/find-files.ts:55). Notably it does
		// not prune obj/ or bin/, so obj/project.assets.json stays
		// discoverable — as it is today.
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

// rootTargetFiles lists the supported target files for a single project rooted
// at dir, without descending into arbitrary subdirectories.
//
// obj/ is the one directory it does look into: restore writes
// project.assets.json there, and detect.ts allows exactly that path
// (obj/project.assets.json, src/lib/detect.ts:29). Without it a default scan of
// an SDK-style project would find nothing at all.
func rootTargetFiles(dir string) ([]discovery.FindResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	// FindResult.Path is documented as absolute, and discovery.FindFiles
	// resolves it that way. Match that here: dir is frequently "." (the
	// dep-graph workflow's default input directory), and a relative Path would
	// leave the project with no directory to be named after.
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

// isSupportedTargetFile reports whether path's file name is one this plugin
// recognizes. Only the base name is considered, matching how discovery applies
// its include patterns — so --file=obj/project.assets.json is accepted, which
// is the form detect.ts allows (src/lib/detect.ts:29).
func isSupportedTargetFile(path string) bool {
	base := filepath.Base(path)

	for _, name := range targetFileNames {
		if base == name {
			return true
		}
	}

	return false
}
