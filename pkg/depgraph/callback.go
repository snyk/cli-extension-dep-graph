package depgraph

import (
	_ "embed"

	"github.com/snyk/cli-extension-dep-graph/internal/uv"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	contentTypeJSON        = "application/json"
	legacyCLIWorkflowIDStr = "legacycli"
	contentLocationKey     = "Content-Location"
)

//nolint:gochecknoglobals // Workflow identifier needs to be a package-level variable
var legacyWorkflowID = workflow.NewWorkflowIdentifier(legacyCLIWorkflowIDStr)

func callback(ctx workflow.InvocationContext, data []workflow.Data) ([]workflow.Data, error) {
	return callbackWithDI(ctx, data, uv.NewUvClient())
}

func callbackWithDI(ctx workflow.InvocationContext, _ []workflow.Data, uvClient uv.Client) ([]workflow.Data, error) {
	engine := ctx.GetEngine()
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	logger.Print("DepGraph workflow start")

	// Check if SBOM resolution mode is enabled
	if config.GetBool(FlagUseSBOMResolution) {
		scaPlugins := []scaplugin.ScaPlugin{
			uv.NewUvPlugin(uvClient),
		}
		return handleSBOMResolution(ctx, config, logger, scaPlugins)
	}

	return handleLegacyResolution(engine, config, logger)
}
