package ecosystems

import (
	"context"
	"slices"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// AnnotatedPluginResult pairs a *PluginResult with the SCAPlugin that produced
// it, so callers can apply per-plugin behavior (e.g. plugin-name-conditional
// conversion) after the runner has finished iterating.
type AnnotatedPluginResult struct {
	Plugin SCAPlugin
	*PluginResult
}

// RunPluginsSequentially executes plugins in order, returning each plugin's
// result paired with the plugin itself.
//
//nolint:gocritic // hugeParam: opts is intentionally passed by value so callers' state isn't mutated
func RunPluginsSequentially(
	ctx context.Context,
	log logger.Logger,
	dir string,
	opts SCAPluginOptions,
	plugins []SCAPlugin,
) (results []AnnotatedPluginResult, failFastResult *SCAResult, err error) {
	// Clone Exclude so the per-iteration appends don't reach into the caller's backing array.
	opts.Global.Exclude = slices.Clone(opts.Global.Exclude)

	for _, plugin := range plugins {
		pluginResult, pluginErr := plugin.BuildDepGraphsFromDir(ctx, log, dir, &opts)
		if pluginErr != nil {
			return nil, nil, pluginErr //nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog
		}
		if pluginResult == nil {
			continue
		}

		if opts.Global.FailFast && opts.Global.AllProjects {
			for _, r := range pluginResult.Results {
				if r.Error != nil {
					triggering := r
					//nolint:nilerr // per-result error is surfaced via failFastResult
					return results, &triggering, nil
				}
			}
		}

		results = append(results, AnnotatedPluginResult{Plugin: plugin, PluginResult: pluginResult})

		if !opts.Global.AllProjects && len(pluginResult.Results) > 0 {
			break
		}

		opts.WithExclude(pluginResult.ProcessedFiles)
	}

	return results, nil, nil
}
