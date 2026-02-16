package depgraph

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
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

	return ResolveDepgraphs(ctx, config, logger, handleLegacyResolution)
}
