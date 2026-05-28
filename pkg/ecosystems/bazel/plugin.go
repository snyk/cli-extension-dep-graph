package bazel

import (
	"context"
	"errors"
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

const (
	pluginName = "bazel"
	// defaultMaxTargets caps target enumeration to protect Snyk from runaway
	// scans on monorepos that match an overly broad --bazel-target-query. The
	// ceiling can be raised via --bazel-max-targets, or set to 0 to disable.
	defaultMaxTargets = 1000
)

type Plugin struct{}

// Ensures this Plugin satisfies the SCAPlugin interface.
var _ ecosystems.SCAPlugin = new(Plugin)

func (p Plugin) GetName() string {
	return pluginName
}

func (p Plugin) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	dir string,
	options *ecosystems.SCAPluginOptions,
	onGraph func(ecosystems.SCAResult) error,
) error {
	if log == nil {
		log = logger.Nop()
	}

	resolver, err := newResolverFromOptions(dir, options)
	if err != nil {
		if errors.Is(err, errNoBazelOptionFound) {
			log.Debug(ctx, "no bazel option found, skipping bazel dependency graph resolution")
			return nil
		}
		return fmt.Errorf("failed to initialize bazel resolver: %w", err)
	}
	log.Debug(ctx, "using bazel resolver", logger.Attr("type", resolver.packageManagerName()))

	targets, err := resolver.findTargets(ctx, options)
	if err != nil {
		return fmt.Errorf(errQueryBazelTargetsFmt, err)
	}
	log.Debug(ctx, "found bazel targets", logger.Attr("targets", targets))

	if err := checkTargetLimit(len(targets), options); err != nil {
		return err
	}

	// processedFiles for the bazel resolver is computed at the resolver
	// scope (WORKSPACE, MODULE.bazel, etc.), not per target. Attach to
	// every emitted result; downstream consumers dedup.
	processed := resolver.processedFiles()

	emitted := 0
	for _, target := range targets {
		graph, err := resolver.buildDepGraph(ctx, target)
		if err != nil {
			log.Error(ctx, "failed to build graph for bazel target", logger.Attr("target", target), logger.Err(err))
			continue
		}
		log.Debug(ctx, "resolved dep-graph for bazel target", logger.Attr("target", target))

		if err := onGraph(ecosystems.SCAResult{
			DepGraph: graph,
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					ProjectType: resolver.packageManagerName(),
					TargetFile:  &target,
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName:           pluginName,
				NormalisedTargetFile: target,
			},
			ProcessedFiles: processed,
		}); err != nil {
			return err
		}
		emitted++
	}

	if emitted == 0 {
		log.Debug(ctx, "no bazel dependency graphs resolved")
	}

	return nil
}

// checkTargetLimit returns an error when the number of discovered targets
// exceeds the configured ceiling. The ceiling defaults to defaultMaxTargets;
// an explicit --bazel-max-targets value overrides it, and a value of 0
// disables the check entirely.
func checkTargetLimit(count int, options *ecosystems.SCAPluginOptions) error {
	limit := defaultMaxTargets
	if options != nil && options.Bazel.MaxTargets != nil {
		limit = *options.Bazel.MaxTargets
	}
	if limit <= 0 || count <= limit {
		return nil
	}
	return fmt.Errorf(
		"bazel target count %d exceeds the safe limit of %d; raise with --bazel-max-targets=N or disable with --bazel-max-targets=0",
		count, limit,
	)
}
