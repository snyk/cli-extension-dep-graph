package conversion

import (
	"context"
	"fmt"
	"io"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/internal/snykclient"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// RemoteSBOMConverter implements SBOMConverter by calling the remote conversion endpoint.
type RemoteSBOMConverter struct {
	client *snykclient.SnykClient
	log    logger.Logger
}

// NewRemoteSBOMConverter creates a converter that calls the remote conversion endpoint.
func NewRemoteSBOMConverter(client *snykclient.SnykClient, log logger.Logger) *RemoteSBOMConverter {
	return &RemoteSBOMConverter{client: client, log: log}
}

// ConvertSBOM sends the SBOM to the conversion endpoint and returns the resulting dep-graphs,
// along with any warnings produced during conversion.
func (c *RemoteSBOMConverter) ConvertSBOM(
	ctx context.Context,
	sbom io.Reader,
	options ConvertSBOMOptions,
) ([]*depgraph.DepGraph, []Warning, error) {
	scans, snykWarnings, err := c.client.SBOMConvert(ctx, c.log, sbom, options.RemoteRepoURL, options.ForceSingleGraph)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert SBOM: %w", err)
	}

	depGraphs, err := extractDepGraphsFromScans(scans)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract depgraphs from scan results: %w", err)
	}

	warnings := translateWarnings(snykWarnings)
	return depGraphs, warnings, nil
}

func translateWarnings(warnings []*snykclient.ConversionWarning) []Warning {
	if len(warnings) == 0 {
		return nil
	}
	out := make([]Warning, 0, len(warnings))
	for _, w := range warnings {
		if w == nil {
			continue
		}
		out = append(out, Warning{
			Type:   w.Type,
			BOMRef: w.BOMRef,
			Msg:    w.Msg,
		})
	}
	return out
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

// Compile-time check that RemoteSBOMConverter satisfies SBOMConverter.
var _ SBOMConverter = (*RemoteSBOMConverter)(nil)
