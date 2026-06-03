package gradle

import (
	"context"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// NormalizeDepsPostHook is the post-hook signature accepted by the Gradle
// plugin. It rewrites SCA results in place using canonical Maven coordinates
// resolved by SHA1 via the Snyk Packages API.
type NormalizeDepsPostHook = func(
	ctx context.Context,
	log logger.Logger,
	results []ecosystems.SCAResult,
	options *ecosystems.SCAPluginOptions,
) []ecosystems.SCAResult

// NewNormalizeDepsPostHook returns a no-op post-hook that passes results
// through unchanged. The full implementation, which resolves canonical Maven
// coordinates via the Snyk Packages API, is wired in separately.
func NewNormalizeDepsPostHook() NormalizeDepsPostHook {
	return func(
		_ context.Context,
		_ logger.Logger,
		results []ecosystems.SCAResult,
		_ *ecosystems.SCAPluginOptions,
	) []ecosystems.SCAResult {
		return results
	}
}
