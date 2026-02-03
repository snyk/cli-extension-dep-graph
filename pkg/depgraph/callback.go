package depgraph

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/constants"
)

const (
	contentTypeJSON        = "application/json"
	legacyCLIWorkflowIDStr = "legacycli"
	contentLocationKey     = "Content-Location"
)

type ResolutionHandlerFunc func(ctx workflow.InvocationContext, config configuration.Configuration, logger *zerolog.Logger) ([]workflow.Data, error)

func callback(ctx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	logger.Print("DepGraph workflow start")

	if config.GetBool(FlagUseSBOMResolution) {
		return handleSBOMResolution(ctx, config, logger)
	}

	// Get the showMavenBuildScope & showNpmBuildScope flags values & set in instrumentation
	ai := ctx.GetAnalytics()
	ai.AddExtensionBoolValue(constants.ShowMavenBuildScope, config.GetBool(constants.FeatureFlagShowMavenBuildScope))
	ai.AddExtensionBoolValue(constants.ShowNpmScope, config.GetBool(constants.FeatureFlagShowNpmScope))

	return handleLegacyResolution(ctx, config, logger)
}
