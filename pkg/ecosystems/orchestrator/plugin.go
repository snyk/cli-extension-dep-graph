package orchestrator

import (
	"context"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

const PluginName = "orchestrator"

// depgraphResolver is the subset of PluginRegistry the adapter depends on, so the
// channel->callback bridge can be unit-tested with a fake resolver instead of the
// real sub-plugins.
type depgraphResolver interface {
	ResolveDepgraphs(dir string, opts *ecosystems.SCAPluginOptions) <-chan ecosystems.SCAResult
}

// Plugin adapts the channel-based PluginRegistry to the callback-based
// SCAPlugin interface, so the orchestrator (bazel, bun, pnpm, gradle, cargo and
// the legacy CLI) can be dropped into a []SCAPlugin alongside other resolvers.
type Plugin struct {
	ictx workflow.InvocationContext
	// Overridable in tests; defaults to NewDefaultPluginRegistry.
	newRegistry func(workflow.InvocationContext) (depgraphResolver, error)
}

var _ ecosystems.SCAPlugin = (*Plugin)(nil)

// NewPlugin returns an orchestrator-wrapping SCAPlugin. It is a drop-in for
// legacy.NewPlugin(ictx): with every resolver feature flag off the orchestrator
// runs only the legacy plugin, so behavior is preserved.
func NewPlugin(ictx workflow.InvocationContext) *Plugin {
	return &Plugin{
		ictx: ictx,
		newRegistry: func(ictx workflow.InvocationContext) (depgraphResolver, error) {
			return NewDefaultPluginRegistry(ictx)
		},
	}
}

func (p *Plugin) GetName() string {
	return PluginName
}

// BuildDepGraphsFromDir builds the registry, drains its results channel and
// forwards each SCAResult to onGraph.
//
// The log argument is ignored: the orchestrator and its sub-plugins log via
// ictx.GetEnhancedLogger() internally.
//
// Contract: a non-nil onGraph return aborts the run. ResolveDepgraphs runs its
// work in a goroutine whose sends are guarded by a select on ctx.Done() over an
// unbuffered channel, so canceling the context is what unblocks it. We derive a
// cancellable child from the ctx argument (the authoritative cancellation signal)
// and feed it to the registry via cancelableICtx; the deferred cancel fires on
// both abort and normal completion, guaranteeing the goroutine unwinds without a
// manual drain loop.
func (p *Plugin) BuildDepGraphsFromDir(
	ctx context.Context,
	_ logger.Logger,
	dir string,
	opts *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	if opts == nil {
		return fmt.Errorf("cannot resolve dependencies without options")
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	orchOpts, err := p.buildOrchestratorOptions(opts)
	if err != nil {
		return err
	}

	registry, err := p.newRegistry(cancelableICtx{InvocationContext: p.ictx, ctx: childCtx})
	if err != nil {
		return fmt.Errorf("failed to create plugin registry: %w", err)
	}

	for result := range registry.ResolveDepgraphs(dir, orchOpts) {
		if err := onGraph(result); err != nil {
			return err
		}
	}
	return nil
}

// buildOrchestratorOptions builds the options the orchestrator's sub-plugins
// expect, mirroring how cli-extension-os-flows constructs them: from the raw CLI
// args, which populate the ecosystem-specific sub-options (Bazel, Python, Gradle)
// and Global.RawFlags. The shared buildPluginOptions in the SBOM flow does not
// set those.
//
// The batch-critical fields are carried over from the incoming options so the
// SBOM flow's cross-plugin propagation still works: ExcludePaths carries the
// files earlier plugins (e.g. uv) already processed, and AllProjects drives
// fan-out.
func (p *Plugin) buildOrchestratorOptions(in *ecosystems.SCAPluginOptions) (*ecosystems.SCAPluginOptions, error) {
	cfg := p.ictx.GetConfiguration()
	out, err := ecosystems.NewPluginOptionsFromRawFlags(cfg.GetStringSlice(configuration.RAW_CMD_ARGS))
	if err != nil {
		return nil, fmt.Errorf("failed to build orchestrator options: %w", err)
	}

	out.Global.ExcludePaths = in.Global.ExcludePaths
	out.Global.AllProjects = in.Global.AllProjects

	return out, nil
}

// cancelableICtx wraps an InvocationContext so Context() returns a caller-supplied
// (cancellable) context. All other methods delegate to the embedded interface.
// This lets the adapter hand the registry a context it can cancel without
// changing ResolveDepgraphs's public signature.
type cancelableICtx struct {
	workflow.InvocationContext
	//nolint:containedctx // intentional: this wrapper exists solely to override Context() with a cancellable child.
	ctx context.Context
}

func (c cancelableICtx) Context() context.Context { return c.ctx }
