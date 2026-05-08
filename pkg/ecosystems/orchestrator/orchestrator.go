package orchestrator

import (
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pip"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/pipenv"
)

// ResolveDepgraphs resolves dependency graphs for a directory by running the
// configured SCA plugins in order and emitting their results on the returned
// channel.
//
//nolint:gocritic // hugeParam: ensure `opts` is not nil
func ResolveDepgraphs(ictx workflow.InvocationContext, dir string, opts ecosystems.SCAPluginOptions) (<-chan ecosystems.SCAResult, error) {
	return resolveDepgraphsDI(ictx, dir, opts, []ecosystems.SCAPlugin{
		pip.Plugin{},
		pipenv.Plugin{},
		legacy.NewPlugin(ictx),
	})
}

//nolint:gocritic // hugeParam: ensure `opts` is not nil
func resolveDepgraphsDI(
	ictx workflow.InvocationContext,
	dir string,
	opts ecosystems.SCAPluginOptions,
	plugins []ecosystems.SCAPlugin,
) (<-chan ecosystems.SCAResult, error) {
	enhancedLogger := ictx.GetEnhancedLogger()
	pluginLogger := logger.NewFromZerolog(enhancedLogger)

	results, failFastResult, err := ecosystems.RunPluginsSequentially(ictx.Context(), pluginLogger, dir, opts, plugins)
	if err != nil {
		return nil, err //nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog
	}
	if failFastResult != nil {
		//nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog
		return nil, ecosystems.HandleFailFastResult(enhancedLogger, *failFastResult)
	}

	var collected []ecosystems.SCAResult
	for _, o := range results {
		collected = append(collected, o.Results...)
	}

	resultsChan := make(chan ecosystems.SCAResult, len(collected))
	for _, r := range collected {
		resultsChan <- r
	}
	close(resultsChan)

	return resultsChan, nil
}
