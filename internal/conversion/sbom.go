package conversion

import (
	"context"
	"fmt"
	"io"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
)

func SbomToDepGraphs(
	ctx context.Context,
	sbom io.Reader,
	metadata *scaplugin.Metadata,
	snykClient *snykclient.SnykClient,
	log logger.Logger,
	remoteRepoURL string,
) ([]*depgraph.DepGraph, error) {
	scans, warnings, err := snykClient.SBOMConvert(ctx, log, sbom, remoteRepoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to convert SBOM: %w", err)
	}

	log.Info(ctx, "Successfully converted SBOM", logger.Attr("warnings", len(warnings)))

	depGraphsData, err := extractDepGraphsFromScans(scans)
	if err != nil {
		return nil, fmt.Errorf("failed to extract depgraphs from scan results: %w", err)
	}

	if len(depGraphsData) == 0 {
		depGraph, err := emptyDepGraph(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to create empty depgraph: %w", err)
		}
		depGraphsData = append(depGraphsData, depGraph)
	}
	return depGraphsData, nil
}

func emptyDepGraph(metadata *scaplugin.Metadata) (*depgraph.DepGraph, error) {
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
	depGraph := builder.Build()
	return depGraph, nil
}

func extractDepGraphsFromScans(scans []*snykclient.ScanResult) ([]*depgraph.DepGraph, error) {
	var depGraphs []*depgraph.DepGraph

	for _, scan := range scans {
		dgs, err := scan.DepGraphs()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve depgraphs: %w", err)
		}
		depGraphs = append(depGraphs, dgs...)
	}

	return depGraphs, nil
}
