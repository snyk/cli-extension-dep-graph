package depgraph

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/uv"
)

type ResolutionHandlerFunc func(ctx gafworkflow.InvocationContext, config configuration.Configuration, logger *zerolog.Logger) ([]gafworkflow.Data, error)

func callback(ctx gafworkflow.InvocationContext, _ []gafworkflow.Data) ([]gafworkflow.Data, error) {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	logger.Print("DepGraph workflow start")

	if shouldUseOrchestratorResolution(config) {
		return handleOrchestratorResolution(ctx, config, logger)
	}

	if shouldUseSBOMResolution(config, logger) {
		return handleSBOMResolution(ctx, config, logger)
	}

	return legacycli.HandleLegacyResolution(ctx, config, logger) //nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog.
}

func shouldUseSBOMResolution(config configuration.Configuration, logger *zerolog.Logger) bool {
	if !uv.IsUvProject(
		config.GetString(configuration.INPUT_DIRECTORY),
		config.GetString(workflow.FlagFile),
		config.GetBool(workflow.FlagAllProjects),
		config,
	) {
		return false
	}

	logger.Info().Msg("uv.lock found and uv feature flag enabled, using SBOM resolution")
	return true
}

func shouldUseOrchestratorResolution(config configuration.Configuration) bool {
	return config.GetBool(workflow.FeatureFlagUseUnifiedTestAPIForOSCliTest)
}
