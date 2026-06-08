package uv

import (
	"context"

	scaecosystems "github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// collectBuildResults drains plugin.buildResults's streaming emit
// into a slice. Some unit tests bypass the public SCAPlugin
// interface to exercise buildResults directly.
func collectBuildResults(
	ctx context.Context,
	plugin Plugin,
	sbom Sbom,
	lockFilePath, lockFileDir string,
	opts *scaecosystems.SCAPluginOptions,
	log logger.Logger,
) ([]scaecosystems.SCAResult, error) {
	var results []scaecosystems.SCAResult
	_, err := plugin.buildResults(ctx, sbom, lockFilePath, lockFileDir, opts, log, func(r scaecosystems.SCAResult) error {
		results = append(results, r)
		return nil
	})
	return results, err
}
