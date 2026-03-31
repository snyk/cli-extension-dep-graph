package uv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"

	"github.com/snyk/cli-extension-dep-graph/internal/conversion"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	scaecosystems "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

type Plugin struct {
	client        Client
	snykClient    *snykclient.SnykClient
	remoteRepoURL string
}

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
	options *scaecosystems.SCAPluginOptions,
) (*scaecosystems.PluginResult, error) {
	var targetFile string
	if options.Global.TargetFile != nil {
		targetFile = *options.Global.TargetFile
	}

	if targetFile != "" && filepath.Base(targetFile) != UvLockFileName {
		log.Info(ctx, "Skipping processing uv plugin", logger.Attr("targetFile", targetFile), logger.Attr("reason", "not a 'uv.lock' file"))
		return &scaecosystems.PluginResult{}, nil
	}

	files, err := p.discoverLockFiles(ctx, inputDir, targetFile, options)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return &scaecosystems.PluginResult{}, nil
	}

	combined := &scaecosystems.PluginResult{}
	for _, file := range files {
		lockFilePath := file.RelPath // e.g., "uv.lock" or "project1/uv.lock"
		lockFileDir := filepath.Dir(lockFilePath)
		log.Info(ctx, "Building dependency graph", logger.Attr("lockFile", lockFilePath)) //nolint:goconst // logger key, not worth a constant

		sbom, err := p.client.ExportSBOM(lockFileDir, options)
		if err != nil {
			log.Error(ctx, "Failed to build dependency graph", logger.Attr("lockFile", lockFilePath), logger.Err(err))
			wrappedErr := fmt.Errorf("failed to build dependency graph for %s: %w", lockFilePath, err)

			errorResult := scaecosystems.SCAResult{
				Metadata: scaecosystems.Metadata{
					TargetFile: lockFilePath,
				},
				Error: wrappedErr,
			}
			combined.Results = append(combined.Results, errorResult)
			continue
		}
		pluginResult, err := p.buildResults(ctx, sbom, lockFilePath, lockFileDir, options, log)
		if err != nil {
			return nil, err
		}
		combined.Results = append(combined.Results, pluginResult.Results...)
		combined.ProcessedFiles = append(combined.ProcessedFiles, pluginResult.ProcessedFiles...)

		if !options.Global.AllProjects {
			// We don't want more than one project
			break
		}
	}

	return combined, nil
}

func (p Plugin) buildResults(
	ctx context.Context,
	sbom Sbom,
	lockFilePath string,
	lockFileDir string,
	options *scaecosystems.SCAPluginOptions,
	log logger.Logger,
) (*scaecosystems.PluginResult, error) {
	parsedSbom, err := parseAndValidateSBOM(sbom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and validate sbom for %s: %w", lockFilePath, err)
	}

	if !options.Global.AllProjects && !options.Global.ForceIncludeWorkspacePackages && !hasProjectRoot(parsedSbom) {
		log.Info(ctx, "No root project found in SBOM", logger.Attr("lockFile", lockFilePath))
		noRootErr := ecosystems.NewUvNoProjectRootError(
			"Found uv workspace with no root project. To scan all workspace members use the --all-projects flag.",
		)
		return &scaecosystems.PluginResult{
			Results: []scaecosystems.SCAResult{{
				Metadata: scaecosystems.Metadata{
					TargetFile: lockFilePath,
				},
				Error: noRootErr,
			}},
		}, nil
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
		options.Global.ForceSingleGraph,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert sbom to dep-graphs for %s: %w", lockFilePath, err)
	}

	result := &scaecosystems.PluginResult{}

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
		for _, name := range []string{PyprojectTomlFileName, RequirementsTxtFileName} {
			result.ProcessedFiles = append(result.ProcessedFiles, filepath.Join(packagePath, name))
		}

		res := scaecosystems.SCAResult{
			DepGraph: depGraph,
			Metadata: scaecosystems.Metadata{
				TargetFile: manifestFile,
			},
		}
		result.Results = append(result.Results, res)
	}

	// TODO(uv): remove the below when we are able to pass these to the CLI correctly. Currently the
	// `--exclude` flag does not accept paths, it only accepts file or dir names, which does not
	// work for our use case.
	if true {
		result.ProcessedFiles = []string{}
	}

	return result, nil
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
	targetFile string,
	options *scaecosystems.SCAPluginOptions,
) ([]discovery.FindResult, error) {
	var findOpts []discovery.FindOption

	switch {
	case options.Global.AllProjects:
		findOpts = []discovery.FindOption{
			discovery.WithInclude(UvLockFileName),
			discovery.WithCommonExcludes(),
		}
		if len(options.Global.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
		}
	default:
		if targetFile != "" {
			findOpts = append(findOpts, discovery.WithTargetFile(targetFile))
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

var _ scaecosystems.SCAPlugin = (*Plugin)(nil)
