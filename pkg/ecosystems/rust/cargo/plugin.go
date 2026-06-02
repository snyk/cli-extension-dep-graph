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
	logFieldMember   = "member"
)

// Plugin implements ecosystems.SCAPlugin for Cargo (Rust) projects.
// It runs `cargo metadata` to enumerate workspace members and `cargo tree
// --locked` to resolve each member's dep graph, in line with the
// unified-scanners principle of preferring native package-manager tooling.
// The same commands run in CLI and SCM surfaces with no per-environment
// branching.
type Plugin struct {
	executor cargoRunner
}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir discovers Cargo.lock files under dir and produces one
// dep graph per workspace member for each lockfile. A non-workspace single
// crate yields one result; an N-member workspace yields N results.
func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	if log == nil {
		log = logger.Nop()
	}

	if options == nil {
		options = ecosystems.NewPluginOptions()
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

		fileResults := p.buildResults(ctx, log, file.RelPath, lockFileAbsDir, exec, options)
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
	exec cargoRunner,
	options *ecosystems.SCAPluginOptions,
) []ecosystems.SCAResult {
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

	log.Info(ctx, "Building cargo dependency graphs", logger.Attr(logFieldLockFile, lockFileRelPath))

	members, err := p.discoverMembers(ctx, lockFileAbsDir, exec)
	if err != nil {
		return errResult(err)
	}
	if len(members) == 0 {
		return errResult(fmt.Errorf("cargo metadata returned no workspace members"))
	}

	allMemberIDs := make(map[string]struct{}, len(members))
	for _, m := range members {
		allMemberIDs[m.Name+"@"+m.Version] = struct{}{}
	}

	var results []ecosystems.SCAResult

	for _, member := range members {
		memberResult := p.buildMemberResult(ctx, log, lockFileRelPath, lockFileAbsDir, lockFileDir, member, allMemberIDs, exec, options)
		results = append(results, memberResult)
	}

	log.Info(ctx, "Successfully built cargo dependency graphs",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr("graphs", len(results)),
	)

	return results
}

// discoverMembers runs cargo metadata in lockFileAbsDir and parses the
// workspace member list. Non-workspace single-crate projects return a single
// member (themselves), so the caller doesn't need a special-case path.
func (p Plugin) discoverMembers(
	ctx context.Context,
	lockFileAbsDir string,
	exec cargoRunner,
) ([]workspaceMember, error) {
	output, err := exec.RunMetadata(ctx, lockFileAbsDir)
	if err != nil {
		return nil, p.wrapRunError(err)
	}
	defer output.Close()

	meta, err := parseMetadata(output)
	if err != nil {
		return nil, fmt.Errorf("parsing cargo metadata: %w", err)
	}

	return meta.members(), nil
}

// buildMemberResult runs cargo tree scoped to a single workspace member and
// builds an SCAResult containing that member's dep graph. Errors are
// captured per-member so a failure in one member doesn't abort the others.
func (p Plugin) buildMemberResult(
	ctx context.Context,
	log logger.Logger,
	lockFileRelPath, lockFileAbsDir, lockFileDir string,
	member workspaceMember,
	allMemberIDs map[string]struct{},
	exec cargoRunner,
	options *ecosystems.SCAPluginOptions,
) ecosystems.SCAResult {
	relManifest, err := filepath.Rel(lockFileAbsDir, member.ManifestPath)
	if err != nil {
		relManifest = cargoTomlFile
	}
	tf := filepath.Join(lockFileDir, relManifest)

	memberErrResult := func(err error) ecosystems.SCAResult {
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

	log.Debug(ctx, "Building dependency graph for workspace member",
		logger.Attr(logFieldLockFile, lockFileRelPath),
		logger.Attr(logFieldMember, member.Name),
	)

	output, err := exec.RunTree(ctx, lockFileAbsDir, cargoTreeOpts{
		Pkg:            member.Name,
		IncludeDev:     options.Global.IncludeDev,
		AllowOutOfSync: options.Global.AllowOutOfSync,
	})
	if err != nil {
		return memberErrResult(p.wrapRunError(err))
	}
	defer output.Close()

	out, err := parseTree(ctx, log, output)
	if err != nil {
		// cargo failures surface here when the subprocess exited non-zero
		// before producing parseable output; classify the chain to surface
		// actionable messages (e.g. lockfile-out-of-sync).
		return memberErrResult(classifyCargoError(fmt.Errorf("parsing cargo tree output for member %s: %w", member.Name, err)))
	}

	memberID := member.Name + "@" + member.Version
	otherMembers := make(map[string]struct{}, len(allMemberIDs)-1)
	for id := range allMemberIDs {
		if id != memberID {
			otherMembers[id] = struct{}{}
		}
	}

	dg, err := buildDepGraph(out, otherMembers)
	if err != nil {
		return memberErrResult(fmt.Errorf("building dep graph for member %s: %w", member.Name, err))
	}

	return ecosystems.SCAResult{
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
	}
}

// wrapRunError converts errors from the cargo runner into user-facing messages.
// It handles the two error paths into the plugin separately:
//
//   - Direct returns from cargoRunner methods (cargo failed to start, binary
//     missing) — checked here via errors.Is on the sentinels.
//   - Errors surfaced through the streaming pipe after cargo exits non-zero
//     (lockfile out of sync, malformed manifest) — those arrive embedded in
//     the parse error chain; classifyCargoError walks that chain.
func (p Plugin) wrapRunError(err error) error {
	if errors.Is(err, errCargoNotFound) {
		return fmt.Errorf(
			"cargo is not installed or not in PATH; install the Rust toolchain to scan this project: %w",
			err,
		)
	}

	return classifyCargoError(fmt.Errorf("running cargo: %w", err))
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
		// CLI flag mapping: `--file=<path>/Cargo.toml` targets the manifest
		// with Cargo.lock resolved alongside. We accept either filename: if
		// the user points at Cargo.toml, normalise to the sibling Cargo.lock.
		// Anything else is not ours to handle.
		targetFile := *options.Global.TargetFile
		base := filepath.Base(targetFile)
		switch base {
		case cargoLockFile:
			// As-is.
		case cargoTomlFile:
			targetFile = filepath.Join(filepath.Dir(targetFile), cargoLockFile)
		default:
			return nil, nil
		}

		files, err := discovery.FindFiles(ctx, dir, discovery.WithTargetFile(targetFile))
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
func (p Plugin) getExecutor() cargoRunner {
	if p.executor != nil {
		return p.executor
	}

	return &cargoCmdExecutor{}
}
