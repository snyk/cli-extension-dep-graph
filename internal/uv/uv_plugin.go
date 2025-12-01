package uv

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/discovery"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
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
		dir := filepath.Dir(file.RelPath)
		logger.Printf("Build dependency graph for %s", file.RelPath)

		finding, err := p.client.ExportSBOM(dir, options)
		if err != nil {
			logger.Printf("Failed to build dependency graph for %s: %v", file.RelPath, err)
			wrappedErr := fmt.Errorf("failed to build dependency graph for %s: %w", file.RelPath, err)
			errorFinding := scaplugin.Finding{
				NormalisedTargetFile: file.RelPath,
				Error:                wrappedErr,
			}
			findings = append(findings, errorFinding)
			continue
		}
		findings = append(findings, *finding)
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
			discovery.WithInclude(UvLockFileName),
			discovery.WithCommonExcludes(),
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
