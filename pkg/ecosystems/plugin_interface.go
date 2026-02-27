package ecosystems

import (
	"context"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// Metadata contains contextual information about the dependency graph,
// such as the target file and runtime environment.
type Metadata struct {
	TargetFile string `json:"targetFile"`
	Runtime    string `json:"runtime"`
}

// SCAResult represents the result of a Software Composition Analysis (SCA),
// containing the dependency graph and associated metadata.
type SCAResult struct {
	DepGraph *depgraph.DepGraph `json:"depGraph,omitempty"`
	Metadata Metadata           `json:"metadata"`
	Error    error              `json:"error,omitempty"`
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
