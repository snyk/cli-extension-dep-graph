// Package cocoapods is an SCAPlugin that resolves a project's pod
// dependency graph by natively parsing Podfile.lock.
//
// CocoaPods' own CLI is macOS-only (Ruby + the cocoapods gem) and its
// graph-producing subcommands (`pod install`, `pod update`) mutate the
// project's `Pods/` directory. Both properties violate the SCA plugin
// principles (offline, install-free, cross-platform), so this plugin
// reads Podfile.lock directly — the lockfile is YAML with a stable
// schema (PODS / DEPENDENCIES / SPEC REPOS / EXTERNAL SOURCES /
// CHECKOUT OPTIONS / SPEC CHECKSUMS / COCOAPODS / PODFILE CHECKSUM).
//
// Identity, label keys, and subspec deduplication match the legacy
// @snyk/snyk-cocoapods-plugin TypeScript implementation exactly.
package cocoapods

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const logFieldLockFile = "lockFile"

// Plugin implements ecosystems.SCAPlugin for CocoaPods projects.
type Plugin struct{}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// GetName returns the plugin's stable identifier ("cocoapods").
func (p Plugin) GetName() string { return PluginName }

// BuildDepGraphsFromDir discovers Podfile.lock files under dir and emits
// one SCAResult per lockfile via onGraph. CocoaPods is single-project
// per Podfile.lock (no workspace concept) so each lockfile produces
// exactly one dep graph.
//
// Discovery honors:
//   - --target-file: only when it points at a Podfile.lock (or a
//     companion manifest in the same directory; we resolve to the
//     adjacent Podfile.lock).
//   - --all-projects: scans recursively, skipping common excludes
//     (node_modules, .git, etc.) plus any user-supplied --exclude /
//     --exclude-paths globs.
//   - default: probes only the root directory's Podfile.lock.
//
// Discovery never recurses into `Pods/`: that directory is a CocoaPods
// install artefact and would yield duplicate sub-lockfiles for vendored
// pods that already appear in the parent lockfile.
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
		log.Debug(ctx, "No Podfile.lock files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered Podfile.lock files", logger.Attr("count", len(files)))

	for _, file := range files {
		result := p.buildResult(ctx, log, file.Path, file.RelPath)
		if err := onGraph(result); err != nil {
			return err
		}
	}

	return nil
}

// buildResult parses one Podfile.lock and returns the SCAResult to emit.
// On any error the result is returned with Error set rather than aborting
// the whole run — this matches the SCAPlugin contract (per-graph build
// failures surface via onGraph, not as the BuildDepGraphsFromDir return).
func (p Plugin) buildResult(
	ctx context.Context,
	log logger.Logger,
	lockfileAbs, lockfileRel string,
) ecosystems.SCAResult {
	lockfileDir := filepath.Dir(lockfileAbs)
	relLockDir := filepath.Dir(lockfileRel)

	// Resolve the project's target file. Prefer a Podfile-style
	// manifest in the same directory (legacy plugin priority order);
	// fall back to the lockfile itself when none exists.
	targetRel := lockfileRel
	if name, ok := findManifestFile(lockfileDir); ok {
		targetRel = filepath.Join(relLockDir, name)
	}

	rootName := filepath.Base(lockfileDir)
	processed := []string{lockfileRel}
	if targetRel != lockfileRel {
		processed = append(processed, targetRel)
	}

	errResult := func(err error) ecosystems.SCAResult {
		tf := targetRel
		return ecosystems.SCAResult{
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType: pkgManagerName,
					TargetFile:  &tf,
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName:           PluginName,
				NormalisedTargetFile: tf,
			},
			ProcessedFiles: processed,
			Error:          err,
		}
	}

	log.Info(ctx, "Building cocoapods dependency graph", logger.Attr(logFieldLockFile, lockfileRel))

	lock, err := ReadLockfile(lockfileAbs)
	if err != nil {
		log.Error(ctx, "Failed to read Podfile.lock", logger.Attr(logFieldLockFile, lockfileRel), logger.Err(err))
		return errResult(err)
	}

	graph, err := BuildDepGraph(lock, rootName, defaultRootVersion)
	if err != nil {
		log.Error(ctx, "Failed to build cocoapods dep graph", logger.Attr(logFieldLockFile, lockfileRel), logger.Err(err))
		return errResult(fmt.Errorf("building dep graph: %w", err))
	}

	log.Info(ctx, "Successfully built cocoapods dependency graph",
		logger.Attr(logFieldLockFile, lockfileRel),
		logger.Attr("pods", len(lock.Pods)),
	)

	tf := targetRel
	return ecosystems.SCAResult{
		DepGraph: graph,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       pkgManagerName,
				TargetFile:        &tf,
				RootComponentName: rootName,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			VersionBuildInfo:     map[string]string{},
			NormalisedTargetFile: tf,
		},
		ProcessedFiles: processed,
	}
}

// findManifestFile probes the lockfile directory for a Podfile-style
// manifest in the legacy plugin's priority order:
//
//	CocoaPods.podfile.yaml → CocoaPods.podfile → Podfile → Podfile.rb
//
// Returns the first one found; ok=false means none exist (the lockfile
// itself becomes the TargetFile).
func findManifestFile(dir string) (string, bool) {
	for _, name := range manifestPriority {
		if fileExists(filepath.Join(dir, name)) {
			return name, true
		}
	}
	return "", false
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// discoverLockFiles resolves the Podfile.lock file(s) to scan based on
// the requested options (target-file, all-projects, or default
// root-only).
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
		return p.discoverFromTargetFile(ctx, dir, *options.Global.TargetFile)

	case options.Global.AllProjects:
		return p.discoverAllProjects(ctx, dir, options)

	default:
		rootLock := filepath.Join(dir, lockfileName)
		if !fileExists(rootLock) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: rootLock, RelPath: lockfileName}}, nil
	}
}

// discoverFromTargetFile handles --target-file by accepting either a
// Podfile.lock or a manifest filename. When the user points at a
// manifest, we look up the sibling Podfile.lock — the lockfile is what
// we actually parse, but the manifest is a legitimate way to identify a
// CocoaPods project.
func (p Plugin) discoverFromTargetFile(
	ctx context.Context,
	dir, targetFile string,
) ([]discovery.FindResult, error) {
	base := filepath.Base(targetFile)
	if base == lockfileName {
		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(targetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering Podfile.lock: %w", err)
		}
		return files, nil
	}

	// Manifest-style target file: only valid if it's one of the
	// recognised Podfile variants. Otherwise return empty (signal to
	// the orchestrator that this plugin doesn't handle this file).
	if !isPodfileManifest(base) {
		return nil, nil
	}

	companion := filepath.Join(filepath.Dir(targetFile), lockfileName)
	files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(companion))
	if err != nil {
		return nil, fmt.Errorf("discovering companion Podfile.lock: %w", err)
	}
	return files, nil
}

func isPodfileManifest(name string) bool {
	for _, m := range manifestPriority {
		if name == m {
			return true
		}
	}
	return false
}

// discoverAllProjects walks the directory tree for Podfile.lock files,
// skipping common excludes plus any user-supplied --exclude /
// --exclude-paths globs, and the CocoaPods install directory `Pods/`
// (which can contain its own Manifest.lock that would otherwise be
// picked up by an unsuspecting glob).
func (p Plugin) discoverAllProjects(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	findOpts := []discovery.FindOption{
		discovery.WithInclude(lockfileName),
		discovery.WithCommonExcludes(),
		discovery.WithExclude("Pods"),
	}
	if len(options.Global.Exclude) > 0 {
		findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
	}
	if len(options.Global.ExcludePaths) > 0 {
		findOpts = append(findOpts, discovery.WithExcludes(options.Global.ExcludePaths...))
	}

	files, err := discovery.FindFiles(ctx, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("discovering Podfile.lock files: %w", err)
	}
	return files, nil
}
