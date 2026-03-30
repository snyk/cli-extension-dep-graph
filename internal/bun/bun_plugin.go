package bun

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
)

// Plugin implements scaplugin.SCAPlugin for bun.lock v1.
type Plugin struct {
	executor cmdExecutor
}

// NewBunPlugin creates a new bun plugin instance.
func NewBunPlugin() Plugin {
	return Plugin{}
}

var _ scaplugin.SCAPlugin = (*Plugin)(nil)

func (p Plugin) getExecutor() cmdExecutor {
	if p.executor != nil {
		return p.executor
	}

	return &bunCmdExecutor{}
}

// BuildFindingsFromDir discovers bun.lock files under dir and returns findings.
//
// When the bun binary is available (≥ 1.1.0), `bun why "*"` is used for
// accurate transitive resolution. Otherwise, the plugin falls back to direct
// bun.lock parsing.
func (p Plugin) BuildFindingsFromDir(
	ctx context.Context,
	inputDir string,
	options *scaplugin.Options,
	log logger.Logger,
) ([]scaplugin.Finding, error) {
	if options.TargetFile != "" && filepath.Base(options.TargetFile) != BunLockFileName {
		log.Info(ctx, "Skipping bun plugin", logger.Attr("targetFile", options.TargetFile), logger.Attr("reason", "not a 'bun.lock' file"))
		return []scaplugin.Finding{}, nil
	}

	files, err := p.discoverLockFiles(ctx, inputDir, options)
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return []scaplugin.Finding{}, nil
	}

	findings := []scaplugin.Finding{}

	for _, file := range files {
		lockFilePath := file.RelPath
		lockFileAbsDir := filepath.Dir(filepath.Join(inputDir, lockFilePath))
		lockFileAbsPath := filepath.Join(inputDir, lockFilePath)

		log.Info(ctx, "Building bun dependency graph", logger.Attr("lockFile", lockFilePath))

		finding, err := p.buildFinding(ctx, lockFileAbsPath, lockFileAbsDir, lockFilePath, options, log)
		if err != nil {
			log.Error(ctx, "Failed to build bun dependency graph", logger.Attr("lockFile", lockFilePath), logger.Err(err))
			findings = append(findings, scaplugin.Finding{
				LockFile: lockFilePath,
				Error:    fmt.Errorf("failed to build dependency graph for %s: %w", lockFilePath, err),
			})

			continue
		}

		findings = append(findings, finding...)

		if !options.AllProjects {
			break
		}
	}

	return findings, nil
}

func (p Plugin) buildFinding(
	ctx context.Context,
	lockFileAbsPath, lockFileAbsDir, lockFileRelPath string,
	options *scaplugin.Options,
	log logger.Logger,
) ([]scaplugin.Finding, error) {
	exec := p.getExecutor()

	output, err := exec.Execute("bun", lockFileAbsDir, "why", "*")
	if err != nil {
		if errors.Is(err, ErrBunNotFound) {
			log.Info(ctx, "bun binary not found; falling back to bun.lock parsing")
			return p.buildFindingFromLockfile(ctx, lockFileAbsPath, lockFileAbsDir, lockFileRelPath, options, log)
		}

		return nil, fmt.Errorf("bun why failed: %w", err)
	}

	log.Info(ctx, "Using bun why for dependency resolution")

	return p.buildFindingFromWhyOutput(ctx, output, lockFileAbsPath, lockFileAbsDir, lockFileRelPath, options, log)
}

// buildFindingFromWhyOutput parses bun why output and builds findings.
func (p Plugin) buildFindingFromWhyOutput(
	ctx context.Context,
	output []byte,
	lockFileAbsPath, lockFileAbsDir, lockFileRelPath string,
	options *scaplugin.Options,
	log logger.Logger,
) ([]scaplugin.Finding, error) {
	graph, err := ParseWhyOutput(output)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bun why output: %w", err)
	}

	if options.AllProjects || options.BunWorkspacePackages {
		return p.buildWhyWorkspaceFindings(ctx, graph, lockFileAbsPath, lockFileAbsDir, lockFileRelPath, options, log)
	}

	return p.buildWhySingleFinding(graph, lockFileAbsPath, lockFileAbsDir, lockFileRelPath, options)
}

// buildWhySingleFinding produces one finding for the root workspace using bun why data.
func (p Plugin) buildWhySingleFinding(
	graph *WhyGraph,
	lockFileAbsPath, lockFileAbsDir, lockFileRelPath string,
	options *scaplugin.Options,
) ([]scaplugin.Finding, error) {
	lock, err := ParseLockfile(lockFileAbsPath)
	if err != nil {
		return nil, err
	}

	rootWs := lock.Workspaces[""]
	rootInfo := rootPackageInfo(rootWs, lockFileAbsDir)
	directDeps := mergeDirectDepsAsBool(rootWs, options.Dev)

	depGraph, err := BuildDepGraphFromWhyGraph(rootInfo.Name, rootInfo.Version, directDeps, graph)
	if err != nil {
		return nil, err
	}

	lockFileDir := filepath.Dir(lockFileRelPath)

	return []scaplugin.Finding{{
		DepGraph:     depGraph,
		LockFile:     lockFileRelPath,
		ManifestFile: manifestFilePath(lockFileDir),
	}}, nil
}

// buildWhyWorkspaceFindings produces one finding per workspace using bun why data.
func (p Plugin) buildWhyWorkspaceFindings(
	ctx context.Context,
	graph *WhyGraph,
	lockFileAbsPath, lockFileAbsDir, lockFileRelPath string,
	options *scaplugin.Options,
	log logger.Logger,
) ([]scaplugin.Finding, error) {
	lock, err := ParseLockfile(lockFileAbsPath)
	if err != nil {
		return nil, err
	}

	findings := []scaplugin.Finding{}
	lockFileDir := filepath.Dir(lockFileRelPath)

	for wsPath, ws := range lock.Workspaces {
		var wsAbsDir string
		if wsPath == "" {
			wsAbsDir = lockFileAbsDir
		} else {
			wsAbsDir = filepath.Join(lockFileAbsDir, wsPath)
		}

		rootInfo := rootPackageInfo(ws, wsAbsDir)
		directDeps := mergeDirectDepsAsBool(ws, options.Dev)

		log.Info(ctx, "Building bun workspace dep graph", logger.Attr("workspace", wsPath), logger.Attr("name", rootInfo.Name))

		depGraph, buildErr := BuildDepGraphFromWhyGraph(rootInfo.Name, rootInfo.Version, directDeps, graph)
		if buildErr != nil {
			findings = append(findings, scaplugin.Finding{
				LockFile: lockFileRelPath,
				Error:    fmt.Errorf("failed to build dep graph for workspace %q: %w", wsPath, buildErr),
			})

			continue
		}

		var manifestFile string
		if wsPath == "" {
			manifestFile = manifestFilePath(lockFileDir)
		} else {
			manifestFile = filepath.Join(lockFileDir, wsPath, PackageJSONFileName)
		}

		findings = append(findings, scaplugin.Finding{
			DepGraph:     depGraph,
			LockFile:     lockFileRelPath,
			ManifestFile: manifestFile,
		})
	}

	return findings, nil
}

// buildFindingFromLockfile is the fallback path that parses bun.lock directly.
func (p Plugin) buildFindingFromLockfile(
	ctx context.Context,
	lockFileAbsPath, lockFileAbsDir, lockFileRelPath string,
	options *scaplugin.Options,
	log logger.Logger,
) ([]scaplugin.Finding, error) {
	lock, err := ParseLockfile(lockFileAbsPath)
	if err != nil {
		return nil, err
	}

	pkgMap, err := BuildPackageMap(lock.Packages)
	if err != nil {
		return nil, fmt.Errorf("failed to build package map: %w", err)
	}

	if options.AllProjects || options.BunWorkspacePackages {
		return p.buildWorkspaceFindings(ctx, lock, pkgMap, lockFileAbsDir, lockFileRelPath, options, log)
	}

	return p.buildSingleFinding(lock, pkgMap, lockFileAbsDir, lockFileRelPath, options)
}

// buildSingleFinding produces one finding for the root workspace.
func (p Plugin) buildSingleFinding(
	lock *LockV1,
	pkgMap map[string]*ResolvedPackage,
	lockFileAbsDir, lockFileRelPath string,
	options *scaplugin.Options,
) ([]scaplugin.Finding, error) {
	rootWs := lock.Workspaces[""]
	rootInfo := rootPackageInfo(rootWs, lockFileAbsDir)

	directDeps := mergeDirectDeps(rootWs, options.Dev)
	directDeps = FilterWorkspaceDeps(directDeps)

	depGraph, err := BuildDepGraph(rootInfo.Name, rootInfo.Version, directDeps, pkgMap)
	if err != nil {
		return nil, err
	}

	lockFileDir := filepath.Dir(lockFileRelPath)
	manifestFile := manifestFilePath(lockFileDir)

	return []scaplugin.Finding{{
		DepGraph:     depGraph,
		LockFile:     lockFileRelPath,
		ManifestFile: manifestFile,
	}}, nil
}

// buildWorkspaceFindings produces one finding per workspace entry.
func (p Plugin) buildWorkspaceFindings(
	ctx context.Context,
	lock *LockV1,
	pkgMap map[string]*ResolvedPackage,
	lockFileAbsDir, lockFileRelPath string,
	options *scaplugin.Options,
	log logger.Logger,
) ([]scaplugin.Finding, error) {
	findings := []scaplugin.Finding{}
	lockFileDir := filepath.Dir(lockFileRelPath)

	for wsPath, ws := range lock.Workspaces {
		var wsAbsDir string
		if wsPath == "" {
			wsAbsDir = lockFileAbsDir
		} else {
			wsAbsDir = filepath.Join(lockFileAbsDir, wsPath)
		}

		rootInfo := rootPackageInfo(ws, wsAbsDir)

		directDeps := mergeDirectDeps(ws, options.Dev)
		directDeps = FilterWorkspaceDeps(directDeps)

		log.Info(ctx, "Building bun workspace dep graph", logger.Attr("workspace", wsPath), logger.Attr("name", rootInfo.Name))

		depGraph, err := BuildDepGraph(rootInfo.Name, rootInfo.Version, directDeps, pkgMap)
		if err != nil {
			findings = append(findings, scaplugin.Finding{
				LockFile: lockFileRelPath,
				Error:    fmt.Errorf("failed to build dep graph for workspace %q: %w", wsPath, err),
			})

			continue
		}

		var manifestFile string
		if wsPath == "" {
			manifestFile = manifestFilePath(lockFileDir)
		} else {
			manifestFile = filepath.Join(lockFileDir, wsPath, PackageJSONFileName)
		}

		findings = append(findings, scaplugin.Finding{
			DepGraph:     depGraph,
			LockFile:     lockFileRelPath,
			ManifestFile: manifestFile,
		})
	}

	return findings, nil
}

func (p Plugin) discoverLockFiles(
	ctx context.Context,
	dir string,
	options *scaplugin.Options,
) ([]discovery.FindResult, error) {
	var findOpts []discovery.FindOption

	switch {
	case options.AllProjects:
		findOpts = []discovery.FindOption{
			discovery.WithInclude(BunLockFileName),
			discovery.WithCommonExcludes(),
		}
		if len(options.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Exclude...))
		}
	default:
		if options.TargetFile != "" {
			findOpts = append(findOpts, discovery.WithTargetFile(options.TargetFile))
		} else {
			// Default to root bun.lock if present.
			rootLockPath := filepath.Join(dir, BunLockFileName)
			if fileExists(rootLockPath) {
				return []discovery.FindResult{{
					Path:    rootLockPath,
					RelPath: BunLockFileName,
				}}, nil
			}

			return []discovery.FindResult{}, nil
		}
	}

	files, err := discovery.FindFiles(ctx, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to find bun.lock files: %w", err)
	}

	return files, nil
}

// rootPackageInfo returns name/version for a workspace, falling back to package.json.
func rootPackageInfo(ws Workspace, absDir string) PackageJSON {
	if ws.Name != "" {
		version := ws.Version
		if version == "" {
			version = defaultVersion
		}

		return PackageJSON{Name: ws.Name, Version: version}
	}

	return ReadPackageJSON(absDir)
}

// mergeDirectDeps combines production + optional deps, and dev deps when includeDev is true.
func mergeDirectDeps(ws Workspace, includeDev bool) map[string]string {
	merged := make(map[string]string)

	for k, v := range ws.Dependencies {
		merged[k] = v
	}

	for k, v := range ws.OptionalDependencies {
		merged[k] = v
	}

	if includeDev {
		for k, v := range ws.DevDependencies {
			merged[k] = v
		}
	}

	return merged
}

// mergeDirectDepsAsBool returns the set of direct dep names, excluding workspace: protocol refs.
func mergeDirectDepsAsBool(ws Workspace, includeDev bool) map[string]bool {
	names := make(map[string]bool)

	for name, ver := range ws.Dependencies {
		if !strings.HasPrefix(ver, workspaceProtocol) {
			names[name] = true
		}
	}

	for name, ver := range ws.OptionalDependencies {
		if !strings.HasPrefix(ver, workspaceProtocol) {
			names[name] = true
		}
	}

	if includeDev {
		for name, ver := range ws.DevDependencies {
			if !strings.HasPrefix(ver, workspaceProtocol) {
				names[name] = true
			}
		}
	}

	return names
}

func manifestFilePath(lockFileDir string) string {
	if lockFileDir == "." || lockFileDir == "" {
		return PackageJSONFileName
	}

	return filepath.Join(lockFileDir, PackageJSONFileName)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
