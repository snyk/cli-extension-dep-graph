package uv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"

	"github.com/snyk/cli-extension-dep-graph/pkg/conversion"
	scaecosystems "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

const PluginName = "uv"

type Plugin struct {
	client        Client
	converter     conversion.SBOMConverter
	remoteRepoURL string
}

func NewPlugin(client Client, converter conversion.SBOMConverter, remoteRepoURL string) Plugin {
	return Plugin{
		client:        client,
		converter:     converter,
		remoteRepoURL: remoteRepoURL,
	}
}

func (p Plugin) GetName() string {
	return PluginName
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

	if targetFile != "" && filepath.Base(targetFile) != LockFileName {
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
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						ProjectType: "uv",
						TargetFile:  &lockFilePath,
					},
				},
				ResolverMetadata: &scaecosystems.ResolverMetadata{
					PluginName:           PluginName,
					NormalisedTargetFile: lockFilePath,
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
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						ProjectType: "uv",
						TargetFile:  &lockFilePath,
					},
				},
				ResolverMetadata: &scaecosystems.ResolverMetadata{
					PluginName:           PluginName,
					NormalisedTargetFile: lockFilePath,
				},
				Error: noRootErr,
			}},
		}, nil
	}

	metadata := extractMetadata(parsedSbom)
	workspacePackages := extractWorkspacePackages(parsedSbom)

	depGraphs, err := p.convertWithFallback(ctx, sbom, metadata, options.Global.ForceSingleGraph, log)
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
		for _, name := range []string{LockFileName, PyprojectTomlFileName, RequirementsTxtFileName} {
			result.ProcessedFiles = append(result.ProcessedFiles, filepath.Join(packagePath, name))
		}

		var rootName string
		if rootPkg := depGraph.GetRootPkg(); rootPkg != nil {
			rootName = rootPkg.Info.Name
		}

		res := scaecosystems.SCAResult{
			DepGraph: depGraph,
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType:       "uv",
					TargetFile:        &manifestFile,
					RootComponentName: rootName,
				},
			},
			ResolverMetadata: &scaecosystems.ResolverMetadata{
				PluginName:           PluginName,
				NormalisedTargetFile: manifestFile,
				VersionBuildInfo:     map[string]string{},
			},
		}
		result.Results = append(result.Results, res)
	}

	return result, nil
}

// sbomMetadata is the minimal metadata needed to construct an empty dep-graph
// fallback when an SBOM yields no dep-graphs from conversion.
type sbomMetadata struct {
	PackageManager string
	Name           string
	Version        string
}

// convertWithFallback runs the SBOMConverter and falls back to an empty
// dep-graph built from the SBOM root metadata if the converter returns no
// dep-graphs (e.g. a uv workspace with no dependencies).
func (p Plugin) convertWithFallback(
	ctx context.Context,
	sbom Sbom,
	metadata *sbomMetadata,
	forceSingleGraph bool,
	log logger.Logger,
) ([]*depgraph.DepGraph, error) {
	depGraphs, warnings, err := p.converter.ConvertSBOM(
		ctx,
		bytes.NewReader(sbom),
		conversion.ConvertSBOMOptions{
			RemoteRepoURL:    p.remoteRepoURL,
			ForceSingleGraph: forceSingleGraph,
		},
	)
	if err != nil {
		return nil, err //nolint:wrapcheck // wrapped by caller
	}
	log.Info(ctx, "Successfully converted SBOM", logger.Attr("warnings", len(warnings)))

	if len(depGraphs) == 0 {
		emptyDG, err := buildEmptyDepGraph(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to create empty depgraph: %w", err)
		}
		depGraphs = append(depGraphs, emptyDG)
	}
	return depGraphs, nil
}

// buildEmptyDepGraph creates a dep-graph with just a root package, used as a
// fallback when the SBOM has no dependencies (e.g. a workspace with no deps).
func buildEmptyDepGraph(metadata *sbomMetadata) (*depgraph.DepGraph, error) {
	if metadata.PackageManager == "" {
		return nil, fmt.Errorf("found empty PackageManager on metadata")
	}
	if metadata.Name == "" {
		return nil, fmt.Errorf("found empty Name on metadata")
	}
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: metadata.PackageManager},
		&depgraph.PkgInfo{Name: metadata.Name, Version: metadata.Version},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build depgraph: %w", err)
	}
	return builder.Build(), nil
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
			discovery.WithInclude(LockFileName),
			discovery.WithCommonExcludes(),
		}
		if len(options.Global.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.Exclude...))
		}
		if len(options.Global.ExcludePaths) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Global.ExcludePaths...))
		}
	default:
		if targetFile != "" {
			findOpts = append(findOpts, discovery.WithTargetFile(targetFile))
		} else {
			rootLockPath := filepath.Join(dir, LockFileName)
			// Default to root uv.lock file if it exists
			if fileExists(rootLockPath) {
				findRes := []discovery.FindResult{{
					Path:    rootLockPath,
					RelPath: LockFileName,
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
