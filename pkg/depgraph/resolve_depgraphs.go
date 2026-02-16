package depgraph

import (
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// ResolveDepgraphs orchestrates dependency graph resolution.
// For now it processes the happy path by delegating to the legacy CLI with
// --print-effective-graph-with-errors and basic output parsing. This will be where
// we integrate OS-Flows later. 

func ResolveDepgraphs(
	ctx workflow.InvocationContext,
	config configuration.Configuration,
	logger *zerolog.Logger,
	legacyResolver ResolutionHandlerFunc,
) ([]workflow.Data, error) {
	resolveConfig := config.Clone()
	resolveConfig.Unset(FlagPrintEffectiveGraph)
	resolveConfig.Set(FlagPrintEffectiveGraphWithErrors, true)

	return legacyResolver(ctx, resolveConfig, logger)
}
