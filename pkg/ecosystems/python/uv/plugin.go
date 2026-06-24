package uv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	clierrors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/conversion"
	scaecosystems "github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
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
	onGraph scaecosystems.OnGraphFunc,
) error {
	var targetFile string
	if options.Global.TargetFile != nil {
		targetFile = *options.Global.TargetFile
	}

	if targetFile != "" && filepath.Base(targetFile) != LockFileName {
		log.Info(ctx, "Skipping processing uv plugin", logger.Attr("targetFile", targetFile), logger.Attr("reason", "not a 'uv.lock' file"))
		return nil
	}

	files, err := p.discoverLockFiles(ctx, inputDir, targetFile, options)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}

	for _, file := range files {
		lockFilePath := file.RelPath // e.g., "uv.lock" or "project1/uv.lock"
		lockFileDir := filepath.Dir(lockFilePath)
		// Run uv from the discovered project directory; identity paths stay root-relative.
		exportDir := filepath.Dir(file.Path)
		log.Info(ctx, "Building dependency graph", logger.Attr("lockFile", lockFilePath)) //nolint:goconst // logger key, not worth a constant

		sbom, err := p.client.ExportSBOM(exportDir, options)
		if err != nil {
			log.Error(ctx, "Failed to build dependency graph", logger.Attr("lockFile", lockFilePath), logger.Err(err))
			wrappedErr := fmt.Errorf("failed to build dependency graph for %s: %w", lockFilePath, err)

			manifestFile := manifestPathForRoot(lockFileDir)
			if emitErr := onGraph(scaecosystems.SCAResult{
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						ProjectType: "uv",
						TargetFile:  &manifestFile,
					},
				},
				ResolverMetadata: &scaecosystems.ResolverMetadata{
					PluginName:           PluginName,
					NormalisedTargetFile: manifestFile,
				},
				Error: wrappedErr,
			}); emitErr != nil {
				return emitErr
			}
			continue
		}
		emitted, err := p.buildResults(ctx, sbom, lockFilePath, lockFileDir, options, log, onGraph)
		if err != nil {
			return err
		}

		if (!options.Global.AllProjects || selectedWorkspacePackage(options) != "") && emitted > 0 {
			// We don't want more than one project (a selected workspace package is a single project too).
			break
		}
	}

	return nil
}

// buildResults parses + converts the SBOM and emits one result per
// dep-graph via onGraph. Returns the number emitted so the caller can
// decide whether to break out of the !AllProjects single-project loop.
func (p Plugin) buildResults(
	ctx context.Context,
	sbom Sbom,
	lockFilePath string,
	lockFileDir string,
	options *scaecosystems.SCAPluginOptions,
	log logger.Logger,
	onGraph scaecosystems.OnGraphFunc,
) (int, error) {
	parsedSbom, err := parseAndValidateSBOM(sbom)
	if err != nil {
		return 0, fmt.Errorf("failed to parse and validate sbom for %s: %w", lockFilePath, err)
	}

	workspaceMember := selectedWorkspacePackage(options)

	if !options.Global.AllProjects && !options.Global.ForceIncludeWorkspacePackages &&
		workspaceMember == "" && !hasProjectRoot(parsedSbom) {
		log.Info(ctx, "No root project found in SBOM", logger.Attr("lockFile", lockFilePath))
		noRootErr := ecosystems.NewUvNoProjectRootError(
			"Found uv workspace with no root project. To scan all workspace members use the --all-projects flag.",
		)
		manifestFile := manifestPathForRoot(lockFileDir)
		return 1, onGraph(scaecosystems.SCAResult{
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType: "uv",
					TargetFile:  &manifestFile,
				},
			},
			ResolverMetadata: &scaecosystems.ResolverMetadata{
				PluginName:           PluginName,
				NormalisedTargetFile: manifestFile,
			},
			Error: noRootErr,
		})
	}

	metadata := extractMetadata(parsedSbom)
	workspacePackages := extractWorkspacePackages(parsedSbom)

	depGraphs, err := p.convertWithFallback(ctx, sbom, metadata, options.Global.ForceSingleGraph, log)
	if err != nil {
		return 0, fmt.Errorf("failed to convert sbom to dep-graphs for %s: %w", lockFilePath, err)
	}

	if workspaceMember != "" {
		depGraphs = filterDepGraphsByName(depGraphs, workspaceMember)
		if len(depGraphs) == 0 {
			log.Info(ctx, "Workspace package not found", logger.Attr("workspacePackage", workspaceMember), logger.Attr("lockFile", lockFilePath))
			return 1, onGraph(workspacePackageNotFoundResult(workspaceMember, manifestPathForRoot(lockFileDir)))
		}
	}

	emitted := 0
	for _, depGraph := range depGraphs {
		workspacePackage := findWorkspacePackage(depGraph, workspacePackages)
		result := buildSCAResult(depGraph, lockFileDir, workspacePackage)
		if emitErr := onGraph(result); emitErr != nil {
			return emitted, emitErr
		}
		emitted++
	}

	return emitted, nil
}

// manifestPathForRoot returns the pyproject.toml path used for uv project identity.
// lockFileDir is relative to the input directory; "." maps to the bare filename.
func manifestPathForRoot(lockFileDir string) string {
	if lockFileDir == "." {
		return PyprojectTomlFileName
	}
	return filepath.Join(lockFileDir, PyprojectTomlFileName)
}

// buildSCAResult constructs the SCAResult for a single dep-graph, deriving the
// manifest path and processed files from the (optional) workspace package.
func buildSCAResult(depGraph *depgraph.DepGraph, lockFileDir string, workspacePackage *WorkspacePackage) scaecosystems.SCAResult {
	var manifestFile string
	switch {
	case workspacePackage != nil:
		manifestFile = filepath.Join(lockFileDir, workspacePackage.Path, PyprojectTomlFileName)
	default:
		manifestFile = manifestPathForRoot(lockFileDir)
	}

	packagePath := lockFileDir
	if workspacePackage != nil {
		packagePath = filepath.Join(packagePath, workspacePackage.Path)
	}
	processedFiles := make([]string, 0, 3)
	for _, name := range []string{LockFileName, PyprojectTomlFileName, RequirementsTxtFileName} {
		processedFiles = append(processedFiles, filepath.Join(packagePath, name))
	}

	var rootName string
	if rootPkg := depGraph.GetRootPkg(); rootPkg != nil {
		rootName = rootPkg.Info.Name
	}

	return scaecosystems.SCAResult{
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
		ProcessedFiles: processedFiles,
	}
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

// selectedWorkspacePackage returns the requested workspace member name, or "" if none.
func selectedWorkspacePackage(options *scaecosystems.SCAPluginOptions) string {
	if options.Global.WorkspacePackage != nil {
		return *options.Global.WorkspacePackage
	}
	return ""
}

// filterDepGraphsByName keeps only the dep-graphs whose root package matches name.
func filterDepGraphsByName(depGraphs []*depgraph.DepGraph, name string) []*depgraph.DepGraph {
	var filtered []*depgraph.DepGraph
	for _, dg := range depGraphs {
		if rootPkg := dg.GetRootPkg(); rootPkg != nil && rootPkg.Info.Name == name {
			filtered = append(filtered, dg)
		}
	}
	return filtered
}

// workspacePackageNotFoundResult builds an errored result for a missing workspace member.
func workspacePackageNotFoundResult(pkg, manifestFile string) scaecosystems.SCAResult {
	return scaecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				ProjectType: "uv",
				TargetFile:  &manifestFile,
			},
		},
		ResolverMetadata: &scaecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: manifestFile,
		},
		Error: clierrors.NewGeneralSCAFailureError(fmt.Sprintf("Workspace package '%s' not found.", pkg)),
	}
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
	case options.Global.AllProjects && selectedWorkspacePackage(options) == "":
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
