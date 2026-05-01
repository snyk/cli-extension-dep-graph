package uv

import (
	"context"
	"io"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/conversion"
)

// MockSBOMConverter is a test double for conversion.SBOMConverter. It records
// call args and returns the configured DepGraphs/Warnings/Err.
type MockSBOMConverter struct {
	DepGraphs []*depgraph.DepGraph
	Warnings  []conversion.Warning
	Err       error

	// Captured call args
	CalledOptions []conversion.ConvertSBOMOptions
}

func (m *MockSBOMConverter) ConvertSBOM(
	_ context.Context,
	_ io.Reader,
	options conversion.ConvertSBOMOptions,
) ([]*depgraph.DepGraph, []conversion.Warning, error) {
	m.CalledOptions = append(m.CalledOptions, options)
	return m.DepGraphs, m.Warnings, m.Err
}

var _ conversion.SBOMConverter = (*MockSBOMConverter)(nil)
