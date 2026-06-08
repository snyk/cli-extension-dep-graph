package bundler

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

const (
	// PluginName matches the legacy "bundled:rubygems" project type used
	// in the CLI for identity. The orchestrator key is "bundler" to
	// disambiguate from any future native Bundler runtime work.
	PluginName = "bundler"

	gemfileLockName = "Gemfile.lock"
	gemfileName     = "Gemfile"

	logFieldLockFile = "lockFile"
)

// Plugin implements ecosystems.SCAPlugin for Bundler projects via a
// native Gemfile.lock parser (no `bundle install`, no `bundle viz`,
// no network).
//
// Approach is a forced exception to the "delegate to the package
// manager's CLI" principle: every bundler subcommand that emits a dep
// graph requires `bundle install` first (which mutates the project
// directory). The lockfile is well-spec'd plain text, so native parsing
// is the only offline-and-install-free option.
type Plugin struct{}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func (p Plugin) GetName() string { return PluginName }

// BuildDepGraphsFromDir discovers Gemfile.lock files under dir and
// produces a dep graph per lockfile. Bundler has no workspace concept,
// so each lockfile yields exactly one SCAResult.
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

	files, err := p.discoverLockFiles(ctx, dir, options)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		log.Debug(ctx, "No Gemfile.lock files found", logger.Attr("dir", dir))
		return nil
	}

	log.Debug(ctx, "Discovered Gemfile.lock files", logger.Attr("count", len(files)))

	for _, f := range files {
		result := p.buildResult(ctx, log, dir, f.Path, f.RelPath, options)
		if result.Error != nil {
			log.Error(ctx, "Failed to build bundler dependency graph",
				logger.Attr(logFieldLockFile, f.RelPath),
				logger.Err(result.Error),
			)
		}
		if err := onGraph(result); err != nil {
			return err
		}
	}
	return nil
}

// buildResult parses one Gemfile.lock, derives the root identity, and
// constructs the dep graph. All failure modes are funneled into a
// SCAResult{Error: ...} so the orchestrator can surface them per project.
func (p Plugin) buildResult(
	ctx context.Context,
	log logger.Logger,
	scanRoot, absLockPath, relLockPath string,
	options *ecosystems.SCAPluginOptions,
) ecosystems.SCAResult {
	_ = ctx
	rootName := deriveRootName(scanRoot, relLockPath, options)

	errResult := func(err error) ecosystems.SCAResult {
		tf := relLockPath
		return ecosystems.SCAResult{
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType:       PluginName,
					TargetFile:        &tf,
					RootComponentName: rootName,
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName:           PluginName,
				NormalisedTargetFile: relLockPath,
			},
			ProcessedFiles: []string{relLockPath},
			Error:          err,
		}
	}

	f, err := os.Open(absLockPath)
	if err != nil {
		return errResult(fmt.Errorf("reading %s: %w", relLockPath, err))
	}
	defer f.Close()

	lf, err := Parse(f)
	if err != nil {
		return errResult(fmt.Errorf("parsing %s: %w", relLockPath, err))
	}
	if len(lf.Dependencies) == 0 {
		log.Debug(ctx, "Gemfile.lock has no DEPENDENCIES block",
			logger.Attr(logFieldLockFile, relLockPath))
	}

	log.Info(ctx, "Building bundler dependency graph",
		logger.Attr(logFieldLockFile, relLockPath),
		logger.Attr("specs", len(lf.Specs)),
		logger.Attr("directDeps", len(lf.Dependencies)),
	)

	graph, err := BuildDepGraphWithOptions(rootName, "", lf, BuildOptions{
		IncludeDev: options.Global.IncludeDev,
	})
	if err != nil {
		return errResult(fmt.Errorf("building dep graph for %s: %w", relLockPath, err))
	}

	tf := relLockPath
	return ecosystems.SCAResult{
		DepGraph: graph,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType:       PluginName,
				TargetFile:        &tf,
				RootComponentName: graphRootName(graph),
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: relLockPath,
		},
		ProcessedFiles: []string{relLockPath},
	}
}

func graphRootName(g *depgraph.DepGraph) string {
	if g == nil {
		return ""
	}
	root := g.GetRootPkg()
	if root == nil {
		return ""
	}
	return root.Info.Name
}

// deriveRootName matches the legacy identity contract:
//
//	rootPkg.name = basename(root)
//
// Project-name overrides come from the orchestrator-supplied option
// (--project-name).
//
// When the user invokes with --target-file pointing at a nested
// Gemfile.lock, the legacy plugin uses basename(root) (the scan root,
// not the lockfile's parent). We preserve that.
func deriveRootName(scanRoot, relLockPath string, options *ecosystems.SCAPluginOptions) string {
	if options != nil && options.Global.ProjectName != nil && *options.Global.ProjectName != "" {
		return *options.Global.ProjectName
	}
	// For nested lockfiles discovered via --all-projects, suffix the
	// subdirectory so each result has a distinct root name. Plain
	// single-lockfile scans use just the scan root's basename.
	base := filepath.Base(scanRoot)
	subDir := filepath.Dir(relLockPath)
	if subDir == "." || subDir == "" {
		return base
	}
	return filepath.ToSlash(filepath.Join(base, subDir))
}

// discoverLockFiles mirrors javascript/bun's pattern: --target-file
// pins the discovery to a single file (must be a Gemfile or
// Gemfile.lock); --all-projects walks the tree; default is "root dir
// only, no error if missing".
//
// When --target-file names a Gemfile (not Gemfile.lock), we accept it
// and silently look for the sibling Gemfile.lock — matching the legacy
// inspector behavior which treats Gemfile as "use its lockfile".
func (p Plugin) discoverLockFiles(
	ctx context.Context,
	dir string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	switch {
	case options.Global.TargetFile != nil:
		tf := *options.Global.TargetFile
		base := filepath.Base(tf)
		// Accept Gemfile, Gemfile.lock, or a custom-named gemfile (the
		// legacy plugin uses a permissive regex; we match basename
		// suffix here for predictability).
		if !looksLikeGemfile(base) {
			return nil, nil
		}

		// Resolve to the lockfile path. If the targetFile is "Gemfile",
		// look for "Gemfile.lock" alongside it. If it's already the
		// .lock, use it directly.
		lockRel := tf
		if !strings.HasSuffix(base, ".lock") {
			lockRel = tf + ".lock"
		}

		abs := lockRel
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(dir, lockRel)
		}
		if !fileExists(abs) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: abs, RelPath: lockRel}}, nil

	case options.Global.AllProjects:
		findOpts := []discovery.FindOption{
			discovery.WithInclude(gemfileLockName),
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
			return nil, fmt.Errorf("discovering Gemfile.lock files: %w", err)
		}
		return files, nil

	default:
		root := filepath.Join(dir, gemfileLockName)
		if !fileExists(root) {
			return nil, nil
		}
		return []discovery.FindResult{{Path: root, RelPath: gemfileLockName}}, nil
	}
}

// looksLikeGemfile mirrors the legacy regex
// `/.*[gG]emfile.*(\.lock)?.*$/` in plain Go: case-insensitive contains
// "gemfile", with or without ".lock".
func looksLikeGemfile(base string) bool {
	lower := strings.ToLower(base)
	return strings.Contains(lower, "gemfile")
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
