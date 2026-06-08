// Package swiftpm implements an ecosystems.SCAPlugin for Swift Package
// Manager projects.
//
// It shells out to `swift package show-dependencies --format json` against a
// directory containing Package.swift (and ideally Package.resolved so the
// scan is fully offline). This outsources resolution to swift itself —
// including version-resolution overrides, local-path deps, and transitive
// merges — and avoids re-implementing the Package.resolved format in Go.
//
// Requires swift 5.6+ in PATH (the toolchain version that introduced
// `--format json` for `show-dependencies`).
//
// Identity contract follows the legacy snyk-swiftpm-plugin with one
// deliberate divergence: the legacy plugin reconstructed targetFile as
// `${pathToPosix(targetFile)}Package.swift`, which produces e.g.
// "path/toPackage.swift" (missing path separator) when the input was
// "path/to/Package.swift". This plugin produces the correct
// "path/to/Package.swift". See the plugin audit page for context.
package swiftpm

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
	// PluginName is the canonical identifier surfaced in SCAResult.ResolverMetadata.PluginName.
	PluginName = "swiftpm"

	logFieldManifest = "manifest"
)

// Plugin implements ecosystems.SCAPlugin for Swift Package Manager projects.
type Plugin struct {
	executor swiftRunner
}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers Package.swift files under dir and produces
// one dep graph per package. Swift Package Manager has no first-party
// concept of workspaces (path: deps come close but each is its own package);
// each discovered Package.swift therefore produces a single result.
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

	files, err := p.discoverManifests(ctx, dir, options)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		log.Debug(ctx, "No Package.swift files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered Package.swift files", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	for _, file := range files {
		manifestAbsDir := filepath.Dir(file.Path)

		result := p.buildResult(ctx, log, file.RelPath, manifestAbsDir, exec)
		result.ProcessedFiles = append(result.ProcessedFiles, file.RelPath)

		// Surface Package.resolved as a processed file when it exists so the
		// caller can attribute the scan to both manifest and lockfile.
		resolvedRelPath := filepath.Join(filepath.Dir(file.RelPath), packageResolvedFile)
		if fileExists(filepath.Join(manifestAbsDir, packageResolvedFile)) {
			result.ProcessedFiles = append(result.ProcessedFiles, resolvedRelPath)
		}

		if result.Error != nil {
			log.Error(ctx, "Failed to build swiftpm dependency graph",
				logger.Attr(logFieldManifest, file.RelPath),
				logger.Err(result.Error),
			)
		}

		if err := onGraph(result); err != nil {
			return err
		}
	}

	return nil
}

func (p Plugin) buildResult(
	ctx context.Context,
	log logger.Logger,
	manifestRelPath, manifestAbsDir string,
	exec swiftRunner,
) ecosystems.SCAResult {
	// Note: targetFile is the relative path to Package.swift INCLUDING the
	// "Package.swift" basename and a proper path separator between it and
	// any parent directory. This is the audit's expected-divergence point
	// vs the legacy plugin, which dropped the separator.
	rootTargetFile := manifestRelPath

	errResult := func(err error) ecosystems.SCAResult {
		return ecosystems.SCAResult{
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
		}
	}

	log.Info(ctx, "Building swiftpm dependency graph", logger.Attr(logFieldManifest, manifestRelPath))

	manifest, err := readPackageManifest(manifestAbsDir)
	if err != nil {
		return errResult(fmt.Errorf("reading Package.swift: %w", err))
	}

	output, err := exec.Run(ctx, manifestAbsDir, nil)
	if err != nil {
		return errResult(p.wrapRunError(err))
	}
	defer output.Close()

	parsed, err := parseShowDependenciesOutput(output)
	if err != nil {
		return errResult(fmt.Errorf("parsing swift show-dependencies output: %w", err))
	}

	log.Debug(ctx, "Parsed swift show-dependencies output",
		logger.Attr(logFieldManifest, manifestRelPath),
		logger.Attr("topLevelDeps", len(parsed.Dependencies)),
	)

	graph, err := buildDepGraph(manifest.Name, parsed)
	if err != nil {
		return errResult(fmt.Errorf("building dep graph: %w", err))
	}

	log.Info(ctx, "Successfully built swiftpm dependency graph",
		logger.Attr(logFieldManifest, manifestRelPath),
	)

	return ecosystems.SCAResult{
		DepGraph: graph,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       pkgManager,
				TargetFile:        &rootTargetFile,
				RootComponentName: graph.GetRootPkg().Info.Name,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			VersionBuildInfo:     map[string]string{},
			NormalisedTargetFile: rootTargetFile,
		},
	}
}

// parseShowDependenciesOutput consumes a streaming `swift package
// show-dependencies --format json` reader and decodes the root node.
//
// swift prints its fetch/resolve progress to stderr, then writes a single
// JSON object to stdout. We tolerate trailing whitespace; anything else in
// the stream signals a swift bug or an upstream change worth surfacing.
func parseShowDependenciesOutput(r io.Reader) (*depTreeNode, error) {
	var root depTreeNode
	if err := json.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("decoding swift show-dependencies JSON: %w", err)
	}
	return &root, nil
}

// wrapRunError converts errors from swiftCmdExecutor.Run into user-facing
// messages that name the binary and the minimum supported version.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errSwiftNotFound) {
		return fmt.Errorf(
			"swift is not installed or not in PATH; install swift >= %s to scan this project: %w",
			minSwiftVersion, err,
		)
	}

	if errors.Is(err, errSwiftVersionTooLow) {
		return fmt.Errorf(
			"swift >= %s is required for dependency graph resolution: %w",
			minSwiftVersion, err,
		)
	}

	return fmt.Errorf("running swift package show-dependencies: %w", err)
}

// discoverManifests locates Package.swift files. Defaults to a single root
// manifest; honors --target-file and --all-projects in the same shape as
// the npm/yarn plugins.
func (p Plugin) discoverManifests(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	if options == nil {
		options = ecosystems.NewPluginOptions()
	}

	switch {
	case options.Global.TargetFile != nil:
		if filepath.Base(*options.Global.TargetFile) != packageManifestFile {
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering Package.swift files: %w", err)
		}

		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(packageManifestFile),
			discovery.WithCommonExcludes(),
			// .build is already in commonExcludes; .swiftpm is swift's
			// per-user metadata directory and can never contain a project.
			discovery.WithExclude(".swiftpm"),
		}

		if len(options.Global.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
		}
		if len(options.Global.ExcludePaths) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.ExcludePaths...))
		}

		files, err := discovery.FindFiles(ctx, dir, findOpts...)
		if err != nil {
			return nil, fmt.Errorf("discovering Package.swift files: %w", err)
		}

		return files, nil

	default:
		rootManifest := filepath.Join(dir, packageManifestFile)
		if !fileExists(rootManifest) {
			return nil, nil
		}

		return []discovery.FindResult{{Path: rootManifest, RelPath: packageManifestFile}}, nil
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// getExecutor returns the configured executor or the production
// swiftCmdExecutor. Plugin{} zero-value is valid and uses the production
// executor by default.
func (p Plugin) getExecutor() swiftRunner {
	if p.executor != nil {
		return p.executor
	}

	return &swiftCmdExecutor{}
}
