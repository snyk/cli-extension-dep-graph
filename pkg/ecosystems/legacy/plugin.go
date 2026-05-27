package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/internal/ptrutil"
	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/depgraph/parsers"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

const PluginName = "legacycli"

type Resolver struct {
	ictx gafworkflow.InvocationContext
}

func NewPlugin(ictx gafworkflow.InvocationContext) *Resolver {
	return &Resolver{ictx: ictx}
}

func (l *Resolver) GetName() string {
	return PluginName
}

var _ ecosystems.SCAPlugin = (*Resolver)(nil)

// BuildDepGraphsFromDir invokes the legacy CLI workflow and returns its dep graphs as SCAResults.
// Empty results from the legacy CLI (exit code 3, or successful invocation producing no graphs)
// are returned as an empty PluginResult with no error; callers decide what to do based on the
// totals across all plugins.
func (l *Resolver) BuildDepGraphsFromDir(
	ctx context.Context,
	log logger.Logger,
	_ string,
	opts *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("cannot resolve dependencies without options")
	}

	legacyConfig := buildLegacyConfig(l.ictx.GetConfiguration(), opts)

	depGraphs, err := legacycli.InvokeLegacy(l.ictx, legacyConfig, l.ictx.GetEnhancedLogger())
	if err != nil {
		if errors.Is(err, legacycli.ErrNoDepGraphsFound) || legacycli.IsNoProjectFoundError(err) {
			log.Debug(ctx, "No projects found in legacy CLI call")
			return nil, nil //nolint:nilnil // no dep-graphs found, no error
		}
		return nil, fmt.Errorf("error handling legacy workflow: %w", err)
	}

	results := make([]ecosystems.SCAResult, 0, len(depGraphs))
	processedFiles := make([]string, 0, len(depGraphs))
	for i := range depGraphs {
		result := depGraphOutputToSCAResult(ctx, log, &depGraphs[i])
		results = append(results, result)
		processedFiles = append(processedFiles, result.ResolverMetadata.NormalisedTargetFile)
	}

	return &ecosystems.PluginResult{
		Results:        results,
		ProcessedFiles: processedFiles,
	}, nil
}

// buildLegacyConfig clones the live config and applies legacy-CLI-specific transformations.
//
// `opts.Global.ExcludePaths` is the canonical channel by which the orchestrators tell us "skip these files" —
// it carries the user's `--exclude-paths` (parsed onto opts at construction) plus any files earlier plugins
// reported as processed. When non-empty, we write it onto the cloned config's FlagExcludePaths, overriding
// whatever was already there: in every production path the user's `--exclude-paths` is also on opts, so the
// live config's value is a subset of opts and the override is lossless.
func buildLegacyConfig(src configuration.Configuration, opts *ecosystems.SCAPluginOptions) configuration.Configuration {
	cfg := src.Clone()

	cfg.Unset(workflow.FlagPrintEffectiveGraph)

	if cfg.GetBool(workflow.FlagPrintOutputJsonlWithErrors) {
		cfg.Set(workflow.FlagPrintEffectiveGraphWithErrors, false)
	} else {
		cfg.Set(workflow.FlagPrintEffectiveGraphWithErrors, true)
	}

	if len(opts.Global.ExcludePaths) > 0 {
		cfg.Set(workflow.FlagExcludePaths, strings.Join(opts.Global.ExcludePaths, ","))
	}

	return cfg
}

// mapToTargetFileIdentity mirrors registry's mapping from `targetFileFromPlugin` to target file identifier.
func mapToTargetFileIdentity(ctx context.Context, log logger.Logger, targetFile *string) *string {
	if ptrutil.DerefOr(targetFile, "") == "poetry.lock" {
		log.Info(ctx, "rewriting targetFileFromPlugin: 'poetry.lock' → 'pyproject.toml'")
		return new("pyproject.toml")
	}
	return targetFile
}

// depGraphOutputToSCAResult converts a parsed legacy CLI output line to an SCAResult.
// Per-result errors land on result.Error; a partial dep graph alongside an error is
// preserved.
//
// Identity.TargetFile is derived from `targetFileFromPlugin` via mapToDesiredTargetFile
// so it mirrors the both the legacy CLI's body.targetFile and transformation in registry,
// to preserve the identity of projects.
func depGraphOutputToSCAResult(ctx context.Context, log logger.Logger, output *parsers.DepGraphOutput) ecosystems.SCAResult {
	result := ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile:    mapToTargetFileIdentity(ctx, log, output.TargetFileFromPlugin),
				TargetRuntime: output.TargetRuntime,
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName:           PluginName,
			NormalisedTargetFile: output.NormalisedTargetFile,
		},
	}

	// If there's an error in the output, parse as ErrorCatalog so os-flows can render it
	// (expected with --print-effective-graph-with-errors). Use the first error when the
	// JSON API provides multiple.
	if len(output.Error) > 0 {
		if errs, err := snyk_errors.FromJSONAPIErrorBytes(output.Error); err == nil && len(errs) > 0 {
			result.Error = errs[0]
		} else {
			result.Error = errors.New(string(output.Error))
		}
	}

	// Parse the depgraph JSON if present (may be partial even with errors).
	if len(output.DepGraph) > 0 {
		var dg depgraph.DepGraph
		if err := json.Unmarshal(output.DepGraph, &dg); err != nil {
			// JSON parsing failed — this is a real error, not an expected CLI error.
			log.Error(
				ctx,
				"Failed to unmarshal depgraph JSON",
				logger.Attr("err", err),
				logger.Attr("targetFile", output.NormalisedTargetFile),
			)
			// Preserve any per-result CLI error already captured from output.Error; the
			// upstream error is likely more user-meaningful than our parse failure.
			if result.Error == nil {
				result.Error = fmt.Errorf("failed to unmarshal depgraph: %w", err)
			}
			return result
		}

		result.DepGraph = &dg
		result.ProjectDescriptor.Identity.ProjectType = dg.PkgManager.Name

		if rootPkg := dg.GetRootPkg(); rootPkg != nil {
			result.ProjectDescriptor.Identity.RootComponentName = rootPkg.Info.Name
		}
	}

	return result
}
