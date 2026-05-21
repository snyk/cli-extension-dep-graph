package depgraph

import (
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
)

func callback(ctx gafworkflow.InvocationContext, _ []gafworkflow.Data) ([]gafworkflow.Data, error) {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	logger.Print("DepGraph workflow start")

	if config.GetBool(workflow.FlagUseSBOMResolution) {
		return handleSBOMResolution(ctx, config, logger)
	}

	return legacycli.HandleLegacyResolution(ctx, config, logger) //nolint:wrapcheck // must return unwrapped so os-flows can detect and render ErrorCatalog.
}
