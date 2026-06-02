package ecosystems

import (
	"context"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

type ResolverMetadata struct {
	PluginName           string            `json:"pluginName,omitempty"`
	VersionBuildInfo     map[string]string `json:"versionBuildInfo,omitempty"`
	NormalisedTargetFile string            `json:"normalisedTargetFile,omitempty"`
}

// SCAResult represents one Software Composition Analysis result —
// either a successfully-built dep-graph for one project, or an error
// surfaced against the project's descriptor.
//
// ProcessedFiles lists the files this result was derived from
// (lockfile + any manifests consulted). Per-graph attribution; if a
// consumer wants a deduped union across all results, it computes it
// itself.
type SCAResult struct {
	DepGraph          *depgraph.DepGraph         `json:"depGraph,omitempty"`
	ProjectDescriptor identity.ProjectDescriptor `json:"projectDescriptor"`
	ResolverMetadata  *ResolverMetadata          `json:"meta,omitempty"`
	ProcessedFiles    []string                   `json:"processedFiles,omitempty"`
	Error             error                      `json:"error,omitempty"`
}

// OnGraphFunc is the per-graph callback BuildDepGraphsFromDir invokes
// for each emitted SCAResult. See SCAPlugin for the contract.
type OnGraphFunc func(SCAResult) error

// SCAPlugin builds dependency graphs from a directory containing
// project files. Results are emitted one at a time via onGraph as the
// plugin produces them — there is no aggregated return value. This
// lets consumers stream graphs to disk / network without holding the
// full set in memory.
//
// onGraph is invoked exactly once per produced SCAResult. Calls are
// serialized — onGraph need not be goroutine-safe. A non-nil onGraph
// return aborts the run and BuildDepGraphsFromDir returns that error
// to the caller.
//
// Setup-time failures (cannot access dir, options invalid, etc.) are
// returned directly from BuildDepGraphsFromDir without ever invoking
// onGraph. Per-graph build failures are emitted as
// SCAResult{Descriptor: ..., Error: err} via onGraph — the run
// continues so the caller sees every project the plugin attempted.
type SCAPlugin interface {
	BuildDepGraphsFromDir(
		ctx context.Context,
		log logger.Logger,
		dir string,
		options *SCAPluginOptions,
		onGraph OnGraphFunc,
	) error
	GetName() string
}
