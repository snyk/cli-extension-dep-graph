package conversion

import (
	"context"
	"io"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

// SBOMConverter converts a CycloneDX SBOM into one or more dep-graphs.
type SBOMConverter interface {
	ConvertSBOM(
		ctx context.Context,
		sbom io.Reader,
		options ConvertSBOMOptions,
	) ([]*depgraph.DepGraph, []Warning, error)
}

// ConvertSBOMOptions contains conversion settings that may be used by converter
// implementations.
type ConvertSBOMOptions struct {
	RemoteRepoURL    string
	ForceSingleGraph bool
}

// Warning is a warning surfaced during SBOM-to-depgraph conversion.
// It is implementation-agnostic; each implementation translates its upstream
// warning type (e.g. snykclient.ConversionWarning) into this shared shape.
type Warning struct {
	Type   string
	BOMRef string
	Msg    string
}
