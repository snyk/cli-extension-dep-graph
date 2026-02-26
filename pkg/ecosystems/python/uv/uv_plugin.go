package uv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/internal/conversion"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

type Plugin struct {
	client        Client
	snykClient    *snykclient.SnykClient
	remoteRepoURL string
}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

func NewUvPlugin(client Client, snykClient *snykclient.SnykClient, remoteRepoURL string) Plugin {
	return Plugin{
		client:        client,
		snykClient:    snykClient,
		remoteRepoURL: remoteRepoURL,
	}
}

func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	inputDir string,
	options *ecosystems.SCAPluginOptions,
) ([]ecosystems.SCAResult, error) {
	targetFile := options.Global.TargetFile
	if targetFile != nil && filepath.Base(*targetFile) != UvLockFileName {
		log.Info(ctx, "Skipping processing uv plugin",
			logger.Attr("targetFile", targetFile),
			logger.Attr("reason", "not a 'uv.lock' file"))
		return []ecosystems.SCAResult{}, nil
	}

	files, err := p.discoverLockFiles(ctx, inputDir, options)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return []ecosystems.SCAResult{}, nil
	}

	results := []ecosystems.SCAResult{}
	for _, file := range files {
		lockFilePath := file.RelPath // e.g., "uv.lock" or "project1/uv.lock"
		lockFileDir := filepath.Dir(lockFilePath)
		log.Info(ctx, "Building dependency graph", logger.Attr("lockFile", lockFilePath))

		sbom, err := p.client.ExportSBOM(lockFileDir, options)
		if err != nil {
			log.Error(ctx, "Failed to build dependency graph", logger.Attr("lockFile", lockFilePath), logger.Err(err))

			results = append(results, ecosystems.SCAResult{
				Metadata: ecosystems.Metadata{TargetFile: lockFilePath},
				Error:    fmt.Errorf("failed to build dependency graph for %s: %w", lockFilePath, err),
			})
			continue
		}

		fs, err := p.buildFindings(ctx, sbom, lockFilePath, lockFileDir, log)
		if err != nil {
			return nil, err
		}
		results = append(results, fs...)

		if !options.Global.AllProjects {
			// We don't want more than one project
			break
		}
	}
	return results, nil
}

func (p Plugin) buildFindings(
	ctx context.Context,
	sbom SBOM,
	lockFilePath string,
	lockFileDir string,
	log logger.Logger,
) ([]ecosystems.SCAResult, error) {
	parsedSbom, err := parseAndValidateSBOM(sbom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and validate sbom for %s: %w", lockFilePath, err)
	}

	metadata := extractMetadata(parsedSbom)
	workspacePackages := extractWorkspacePackages(parsedSbom)

	depGraphs, err := conversion.SbomToDepGraphs(
		ctx,
		bytes.NewReader(sbom),
		metadata,
		p.snykClient,
		log,
		p.remoteRepoURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert sbom to dep-graphs for %s: %w", lockFilePath, err)
	}

	findings := []ecosystems.SCAResult{}

	for _, depGraph := range depGraphs {
		workspacePackage := findWorkspacePackage(depGraph, workspacePackages)

		var manifestFile string
		switch {
		case workspacePackage != nil:
			manifestFile = filepath.Join(lockFileDir, workspacePackage.Path, PyprojectTomlFileName)
		case lockFileDir == ".":
			manifestFile = PyprojectTomlFileName
		default:
			manifestFile = filepath.Join(lockFileDir, PyprojectTomlFileName)
		}

		packagePath := lockFileDir
		if workspacePackage != nil {
			packagePath = filepath.Join(packagePath, workspacePackage.Path)
		}
		fileExclusions := []string{
			filepath.Join(packagePath, PyprojectTomlFileName),
			filepath.Join(packagePath, RequirementsTxtFileName),
		}
		// TODO(uv): remove the below when we are able to pass these to the CLI correctly. Currently the
		// `--exclude` flag does not accept paths, it only accepts file or dir names, which does not
		// work for our use case.
		if true {
			fileExclusions = []string{}
		}

		findings = append(findings, ecosystems.SCAResult{
			DepGraph: depGraph,
			Metadata: ecosystems.Metadata{
				LockFile:       lockFilePath,
				ManifestFile:   manifestFile,
				FileExclusions: fileExclusions,
			},
		})
	}
	return findings, nil
}

// Returns nil if the package was not found.
func findWorkspacePackage(depGraph *depgraph.DepGraph, workspacePackages []WorkspacePackage) *WorkspacePackage {
	root := depGraph.GetRootPkg()

	for i := range workspacePackages {
		wp := &workspacePackages[i]
		if wp.Name == root.Info.Name {
			return wp
		}
	}
	return nil
}

func (p Plugin) discoverLockFiles(
	ctx context.Context,
	dir string,
	// targetFile string,
	options *ecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	targetFile := options.Global.TargetFile
	var findOpts []discovery.FindOption

	switch {
	case options.Global.AllProjects:
		findOpts = []discovery.FindOption{
			discovery.WithInclude(UvLockFileName),
			discovery.WithCommonExcludes(),
		}
		if len(options.Global.Excludes) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.Excludes...))
		}
	default:
		if targetFile != nil {
			findOpts = append(findOpts, discovery.WithTargetFile(*targetFile))
		} else {
			rootLockPath := filepath.Join(dir, UvLockFileName)
			// Default to root uv.lock file if it exists
			if fileExists(rootLockPath) {
				findRes := []discovery.FindResult{{
					Path:    rootLockPath,
					RelPath: UvLockFileName,
				}}
				return findRes, nil
			}

			// No root uv.lock file and no targetFile specified - return empty slice
			return []discovery.FindResult{}, nil
		}
	}

	files, err := discovery.FindFiles(ctx, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to find uv lockfile(s): %w", err)
	}
	return files, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
