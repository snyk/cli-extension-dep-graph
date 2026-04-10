package ecosystems

import (
	"context"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

// SCAResult represents the result of a Software Composition Analysis (SCA),
// containing the dependency graph and associated project descriptor.
type SCAResult struct {
	DepGraph          *depgraph.DepGraph         `json:"depGraph,omitempty"`
	ProjectDescriptor identity.ProjectDescriptor `json:"projectDescriptor"`
	Error             error                      `json:"error,omitempty"`
}

type PluginResult struct {
	Results        []SCAResult `json:"results"`
	ProcessedFiles []string    `json:"processedFiles"`
}

// SCAPlugin defines the interface for SCA plugins that build dependency graphs
// from a directory containing project files.
type SCAPlugin interface {
	BuildDepGraphsFromDir(ctx context.Context, log logger.Logger, dir string, options *SCAPluginOptions) (*PluginResult, error)
}
