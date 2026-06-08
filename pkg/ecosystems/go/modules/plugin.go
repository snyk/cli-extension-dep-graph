package modules

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
	PluginName       = "gomodules"
	logFieldTarget   = "targetFile"
)

// Plugin implements ecosystems.SCAPlugin for Go module projects
// (go.mod). It shells out to `go list -json -deps ./...` against the
// project sources only — no `go mod download`, no network — and
// converts the resulting JSON stream into a Snyk dep graph.
//
// Requires `go` in PATH and a populated local module cache; missing
// modules surface as `go list` failures rather than triggering an
// implicit fetch (GOPROXY=off in the executor).
//
// The deprecated `Gopkg.lock` (golangdep) format is intentionally not
// handled here — the legacy snyk-go-plugin remains the resolver for
// that ecosystem.
type Plugin struct {
	executor goListRunner

	// Options carries the optional Snyk-CLI-facing knobs (stdlib
	// inclusion, replace-name behaviour). The zero value matches the
	// CLI shim's defaults: UseReplaceName=true (overriding the zero),
	// IncludeStdlib=false. See the Plugin{}.graphOptions method for
	// the resolved defaults.
	Options PluginOptions
}

// PluginOptions captures plugin-scoped configuration that the legacy
// CLI shim passes through via build-plugin-options.ts. Only the
// fields the CLI actually sets today are modelled.
type PluginOptions struct {
	// IncludeStdlib controls whether stdlib imports surface as
	// synthetic `std/<pkg>` nodes.
	// Source: cli/src/lib/package-managers.ts (FF: includeGoStandardLibraryDeps).
	IncludeStdlib bool

	// UseReplaceNameOverride overrides the default replace-name
	// behaviour. Zero value (nil) keeps the legacy hardcoded default
	// of true — matching cli/src/lib/plugins/build-plugin-options.ts:31.
	// Set to a pointer to false to opt out.
	UseReplaceNameOverride *bool
}

// graphOptions resolves the runtime GraphOptions from the plugin's
// configured PluginOptions, applying the legacy defaults (notably
// useReplaceName=true).
func (p Plugin) graphOptions() GraphOptions {
	useReplaceName := true
	if p.Options.UseReplaceNameOverride != nil {
		useReplaceName = *p.Options.UseReplaceNameOverride
	}
	return GraphOptions{
		IncludeStdlib:  p.Options.IncludeStdlib,
		UseReplaceName: useReplaceName,
	}
}

// Compile-time check that Plugin implements the SCAPlugin interface.
var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers go.mod files under dir and produces
// dep graphs for each one. A go.work file at the root expands into
// one result per workspace member (each member's go.mod is resolved
// independently); a plain go.mod yields a single result.
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

	files, err := p.discoverGoModFiles(ctx, dir, options)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		log.Debug(ctx, "No go.mod files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered go.mod files", logger.Attr("count", len(files)))

	exec := p.getExecutor()

	for _, file := range files {
		modDir := filepath.Dir(file.Path)

		result := p.buildResult(ctx, log, file.RelPath, modDir, exec, options)
		if result.Error != nil {
			log.Error(ctx, "Failed to build go modules dependency graph",
				logger.Attr(logFieldTarget, file.RelPath),
				logger.Err(result.Error),
			)
		}
		result.ProcessedFiles = append(result.ProcessedFiles, file.RelPath)
		if err := onGraph(result); err != nil {
			return err
		}
	}

	return nil
}

// buildResult resolves a single go.mod into an SCAResult. modDir is the
// absolute directory containing the go.mod and is used as the `go list`
// working directory; targetFile is the project-relative go.mod path
// stamped onto the descriptor.
func (p Plugin) buildResult(
	ctx context.Context,
	log logger.Logger,
	targetFile, modDir string,
	exec goListRunner,
	options *ecosystems.SCAPluginOptions,
) ecosystems.SCAResult {
	tf := targetFile

	errResult := func(err error) ecosystems.SCAResult {
		return ecosystems.SCAResult{
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType: pkgManager,
					TargetFile:  &tf,
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName:           PluginName,
				NormalisedTargetFile: tf,
			},
			Error: err,
		}
	}

	log.Info(ctx, "Building go modules dependency graph", logger.Attr(logFieldTarget, targetFile))

	// Offline-safe fallback for the root module name when `go list`
	// can't tell us (e.g. a malformed go.mod or a fixture without
	// real packages). Always read the file even on success — the
	// caller might want it on parse failure too.
	fallbackName, modErr := readModulePath(filepath.Join(modDir, goModFile))
	if modErr != nil {
		log.Debug(ctx, "Could not parse go.mod for fallback module name",
			logger.Attr(logFieldTarget, targetFile),
			logger.Err(modErr),
		)
	}
	if fallbackName == "" {
		fallbackName = filepath.Base(modDir)
	}

	runOpts := p.runOptions(options)
	stream, err := exec.Run(ctx, modDir, runOpts)
	if err != nil {
		return errResult(p.wrapRunError(err))
	}
	defer stream.Close()

	pkgs, err := parseGoListOutput(stream)
	if err != nil {
		return errResult(fmt.Errorf("parsing go list output: %w", err))
	}

	graph, err := buildDepGraph(pkgs, fallbackName, p.graphOptions())
	if err != nil {
		return errResult(fmt.Errorf("building dep graph: %w", err))
	}

	log.Info(ctx, "Successfully built go modules dependency graph",
		logger.Attr(logFieldTarget, targetFile),
		logger.Attr("packages", len(pkgs)),
	)

	rootName := graph.GetRootPkg().Info.Name

	return ecosystems.SCAResult{
		DepGraph: graph,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       pkgManager,
				TargetFile:        &tf,
				RootComponentName: rootName,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			VersionBuildInfo:     map[string]string{},
			NormalisedTargetFile: tf,
		},
	}
}

// runOptions translates SCAPluginOptions into the executor's RunOptions.
//
// Currently only the raw flag pass-through is consulted; the legacy CLI
// shim appends extra args (e.g. `-mod=vendor`) via the implicit
// `args[]` array (build-plugin-options.ts:16).
func (p Plugin) runOptions(_ *ecosystems.SCAPluginOptions) RunOptions {
	return RunOptions{}
}

// wrapRunError converts errors from goCmdExecutor.Run into user-facing
// messages with actionable advice.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errGoNotFound) {
		return fmt.Errorf(
			"go is not installed or not in PATH; install Go to scan this project: %w",
			err,
		)
	}
	return fmt.Errorf("running go list: %w", err)
}

// discoverGoModFiles walks dir for go.mod files according to the
// caller's options.
//
//   - If a workspace go.work file exists at dir, it expands into the
//     go.mod of every `use` member (replacing the default single-root
//     discovery).
//   - Otherwise honours --target-file, --all-projects, or the default
//     "look for go.mod at dir's root only" mode.
func (p Plugin) discoverGoModFiles(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	if options == nil {
		options = ecosystems.NewPluginOptions()
	}

	switch {
	case options.Global.TargetFile != nil:
		if filepath.Base(*options.Global.TargetFile) != goModFile {
			return nil, nil
		}
		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(*options.Global.TargetFile))
		if err != nil {
			return nil, fmt.Errorf("discovering go.mod files: %w", err)
		}
		return files, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(goModFile),
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
			return nil, fmt.Errorf("discovering go.mod files: %w", err)
		}
		return files, nil

	default:
		// Workspace mode: a go.work at the root expands into one
		// result per `use` member, each pointing at the member's
		// go.mod. Falls back to plain single-root discovery if go.work
		// is missing or empty.
		if files := workspaceMembers(dir); len(files) > 0 {
			return files, nil
		}

		rootMod := filepath.Join(dir, goModFile)
		if !fileExists(rootMod) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: rootMod, RelPath: goModFile}}, nil
	}
}

// workspaceMembers returns one FindResult per go.work `use` member
// pointing at the member's go.mod. Members without a go.mod are
// silently skipped (rare; usually a typo in go.work).
//
// Returns nil if no go.work exists at dir, on parse error, or if the
// file declares no use members.
func workspaceMembers(dir string) []discovery.FindResult {
	dirs, err := readWorkspaceDirs(filepath.Join(dir, goWorkFile))
	if err != nil || len(dirs) == 0 {
		return nil
	}

	var out []discovery.FindResult
	for _, rel := range dirs {
		abs := filepath.Join(dir, rel, goModFile)
		if !fileExists(abs) {
			continue
		}
		out = append(out, discovery.FindResult{
			Path:    abs,
			RelPath: filepath.Join(rel, goModFile),
		})
	}
	return out
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// getExecutor returns the configured executor or the production
// goCmdExecutor. The Plugin{} zero value is valid and uses the
// production executor by default.
func (p Plugin) getExecutor() goListRunner {
	if p.executor != nil {
		return p.executor
	}
	return &goCmdExecutor{}
}
