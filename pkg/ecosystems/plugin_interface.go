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

// SCAPlugin defines the interface for SCA plugins that build dependency graphs
// from a directory containing project files. Plugins must also describe their
// capabilities for the plugin registry system.
type SCAPlugin interface {
	// BuildDepGraphsFromDir builds dependency graphs from files in the given directory
	BuildDepGraphsFromDir(ctx context.Context, log logger.Logger, dir string, options *SCAPluginOptions) ([]SCAResult, error)
	// Name returns the unique name of the plugin
	Name() string
	// Capability returns the plugin's capability descriptor
	Capability() PluginCapability
}

// PluginCapability describes what manifest files a plugin can handle
type PluginCapability struct {
	// PrimaryManifests are the main manifest files this plugin handles (e.g., "requirements.txt", "Pipfile")
	PrimaryManifests []string

	// RequiredCompanions are files that must exist alongside the primary manifest (e.g., "Pipfile.lock" for "Pipfile")
	RequiredCompanions []string
}
