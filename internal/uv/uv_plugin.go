package uv

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/conversion"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

type Plugin struct {
	client Client
}

func NewUvPlugin(client Client) Plugin {
	return Plugin{
		client: client,
	}
}

func (p Plugin) BuildFindingsFromDir(
	ctx context.Context,
	inputDir string,
	options *scaplugin.Options,
	conversionConfig *scaplugin.ConversionConfig,
	logger *zerolog.Logger,
) ([]scaplugin.Finding, error) {
	files, err := p.discoverLockFiles(ctx, inputDir, options)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return []scaplugin.Finding{}, nil
	}

	findings := []scaplugin.Finding{}
	for _, file := range files {
		lockFilePath := file.RelPath // e.g., "uv.lock" or "project1/uv.lock"
		lockFileDir := filepath.Dir(lockFilePath)
		logger.Printf("Build dependency graph for %s", lockFilePath)

		sbom, err := p.client.ExportSBOM(lockFileDir, options)
		if err != nil {
			logger.Printf("Failed to build dependency graph for %s: %v", lockFilePath, err)
			wrappedErr := fmt.Errorf("failed to build dependency graph for %s: %w", lockFilePath, err)

			errorFinding := scaplugin.Finding{
				NormalisedTargetFile: lockFilePath,
				Error:                wrappedErr,
			}
			findings = append(findings, errorFinding)
			continue
		}
		fs, err := buildFindings(ctx, sbom, lockFilePath, lockFileDir, conversionConfig, logger)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)

		if !options.AllProjects {
			// We don't want more than one project
			break
		}
	}
	return findings, nil
}

func buildFindings(
	ctx context.Context,
	sbom Sbom,
	lockFilePath string,
	lockFileDir string,
	conversionConfig *scaplugin.ConversionConfig,
	logger *zerolog.Logger,
) ([]scaplugin.Finding, error) {
	parsedSbom, err := parseAndValidateSBOM(sbom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse and validate sbom: %w", err)
	}

	metadata := extractMetadata(parsedSbom)
	workspacePackages := extractWorkspacePackages(parsedSbom)

	depGraphs, err := conversion.SbomToDepGraphs(
		ctx,
		bytes.NewReader(sbom),
		metadata,
		conversionConfig.SnykClient,
		logger,
		conversionConfig.RemoteRepoURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert sbom to dep-graphs: %w", err)
	}

	findings := []scaplugin.Finding{}

	for _, depGraph := range depGraphs {
		workspacePackage := findWorkspacePackage(depGraph, workspacePackages)

		var targetFileFromPlugin string
		switch {
		case workspacePackage != nil:
			targetFileFromPlugin = filepath.Join(workspacePackage.Path, PyprojectTomlFileName)
		case lockFileDir == ".":
			targetFileFromPlugin = PyprojectTomlFileName
		default:
			targetFileFromPlugin = filepath.Join(lockFileDir, PyprojectTomlFileName)
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

		finding := scaplugin.Finding{
			DepGraph:             depGraph,
			FileExclusions:       fileExclusions,
			NormalisedTargetFile: lockFilePath,
			TargetFileFromPlugin: targetFileFromPlugin,
		}
		findings = append(findings, finding)
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
	options *scaplugin.Options,
) ([]discovery.FindResult, error) {
	var findOpts []discovery.FindOption

	switch {
	case options.AllProjects:
		findOpts = []discovery.FindOption{
			discovery.WithInclude(UvLockFileName),
			discovery.WithCommonExcludes(),
		}
		if len(options.Exclude) > 0 {
			findOpts = append(findOpts, discovery.WithExcludes(options.Exclude...))
		}
	default:
		// Default: find uv.lock at root only
		findOpts = []discovery.FindOption{
			discovery.WithTargetFile(UvLockFileName),
		}
	}

	files, err := discovery.FindFiles(ctx, dir, findOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to find uv lockfiles: %w", err)
	}
	return files, nil
}

var _ scaplugin.ScaPlugin = (*Plugin)(nil)
