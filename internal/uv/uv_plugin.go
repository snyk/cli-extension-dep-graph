package uv

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/internal/conversion"
	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
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

func (p Plugin) BuildFindingsFromDir(
	ctx context.Context,
	inputDir string,
	options *scaplugin.Options,
	logger *zerolog.Logger,
) ([]scaplugin.Finding, error) {
	if options.TargetFile != "" && filepath.Base(options.TargetFile) != UvLockFileName {
		logger.Printf("Skipping processing uv plugin for %s as it is not a 'uv.lock' file", options.TargetFile)
		return []scaplugin.Finding{}, nil
	}

	files, err := p.discoverLockFiles(ctx, inputDir, options.TargetFile, options)
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
		logger.Printf("Building dependency graph for %s", lockFilePath)

		sbom, err := p.client.ExportSBOM(lockFileDir, options)
		if err != nil {
			logger.Printf("Failed to build dependency graph for %s: %v", lockFilePath, err)
			wrappedErr := fmt.Errorf("failed to build dependency graph for %s: %w", lockFilePath, err)

			errorFinding := scaplugin.Finding{
				LockFile: lockFilePath,
				Error:    wrappedErr,
			}
			findings = append(findings, errorFinding)
			continue
		}
		fs, err := p.buildFindings(ctx, sbom, lockFilePath, lockFileDir, logger)
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

func (p Plugin) buildFindings(
	ctx context.Context,
	sbom Sbom,
	lockFilePath string,
	lockFileDir string,
	logger *zerolog.Logger,
) ([]scaplugin.Finding, error) {
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
		logger,
		p.remoteRepoURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert sbom to dep-graphs for %s: %w", lockFilePath, err)
	}

	findings := []scaplugin.Finding{}

	for _, depGraph := range depGraphs {
		workspacePackage := findWorkspacePackage(depGraph, workspacePackages)

		var manifestFile string
		switch {
		case workspacePackage != nil:
			manifestFile = filepath.Join(workspacePackage.Path, PyprojectTomlFileName)
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

		finding := scaplugin.Finding{
			DepGraph:       depGraph,
			FileExclusions: fileExclusions,
			LockFile:       lockFilePath,
			ManifestFile:   manifestFile,
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
	targetFile string,
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

var _ scaplugin.SCAPlugin = (*Plugin)(nil)
