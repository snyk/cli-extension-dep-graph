package gradle

import (
	"context"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// collectConvert drains convertProjects's streaming emit into a slice.
// Some unit tests bypass the public plugin interface to exercise
// convertProjects directly.
//
//nolint:unused // used by !integration-tagged plugin_test.go.
func collectConvert(
	ctx context.Context,
	p Plugin,
	log logger.Logger,
	parsed *dependencyGraphJSON,
	dir, discoveredBuildFile string,
	opts *ecosystems.SCAPluginOptions,
) ([]ecosystems.SCAResult, []string) {
	var results []ecosystems.SCAResult
	files, err := p.convertProjects(ctx, log, parsed, dir, discoveredBuildFile, opts, func(r ecosystems.SCAResult) error {
		results = append(results, r)
		return nil
	})
	if err != nil {
		panic(err) // unreachable: the collector never returns an error.
	}
	return results, files
}
