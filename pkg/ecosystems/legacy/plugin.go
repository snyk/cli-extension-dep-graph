package legacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
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
		if errors.Is(err, legacycli.ErrNoDepGraphsFound) || legacycli.IsExitCode3(err) {
			log.Debug(ctx, "No projects found in legacy CLI call")
			return &ecosystems.PluginResult{}, nil
		}
		return nil, fmt.Errorf("error handling legacy workflow: %w", err)
	}

	results := make([]ecosystems.SCAResult, 0, len(depGraphs))
	processedFiles := make([]string, 0, len(depGraphs))
	for i := range depGraphs {
		result := depGraphOutputToSCAResult(ctx, log, &depGraphs[i])
		results = append(results, result)
		processedFiles = append(processedFiles, result.ProjectDescriptor.GetTargetFile())
	}

	return &ecosystems.PluginResult{
		Results:        results,
		ProcessedFiles: processedFiles,
	}, nil
}

// buildLegacyConfig clones the live config and applies legacy-CLI-specific transformations.
func buildLegacyConfig(src configuration.Configuration, opts *ecosystems.SCAPluginOptions) configuration.Configuration {
	cfg := src.Clone()

	cfg.Unset(workflow.FlagPrintEffectiveGraph)

	if cfg.GetBool(workflow.FlagPrintOutputJsonlWithErrors) {
		cfg.Set(workflow.FlagPrintEffectiveGraphWithErrors, false)
	} else {
		cfg.Set(workflow.FlagPrintEffectiveGraphWithErrors, true)
	}

	applyProcessedFilesExclusions(cfg, opts.Global.Exclude)

	return cfg
}

// applyProcessedFilesExclusions forwards the runner-accumulated opts.Global.Exclude
// into the legacy CLI's `--exclude-paths` flag. It exists so the legacy CLI can skip
// files that have already been resolved by an earlier plugin in the same orchestration pass.
//
// This is currently a no-op: it requires snyk/cli-extension-dep-graph#152 (which adds
// the workflow.FlagExcludePaths constant + forwards it from this extension) and
// snyk/cli#6741 (which adds the --exclude-paths flag to the legacy CLI itself).
// Once both have landed, we can uncomment the below to enable the real implementation,
// and unskip any associated tests e.g. `Test_processedFilesFlowFromPluginsToExcludeConfig`.
//
// We cannot use the existing `--exclude` flag in the meantime: it only accepts
// basenames and folder names, which would break workspace-style projects where
// multiple packages share the same manifest filename (e.g. several `package.json`
// in different workspace directories).
func applyProcessedFilesExclusions(_ configuration.Configuration, _ ecosystems.CommaSeparatedString) {
	//nolint:gocritic // intentionally retained, to be used when above PRs are merged
	/*
		if len(excludes) == 0 {
			return
		}

		parts := make([]string, 0, len(excludes)+1)
		if existing := cfg.GetString(workflow.FlagExcludePaths); existing != "" {
			parts = append(parts, existing)
		}
		parts = append(parts, []string(excludes)...)
		cfg.Set(workflow.FlagExcludePaths, strings.Join(parts, ","))
	*/
}

// depGraphOutputToSCAResult converts a parsed legacy CLI output line to an SCAResult. Per-result
// errors are placed on result.Error; a partial dep graph alongside an error is preserved.
//
// Identity.TargetFile is always set to output.NormalisedTargetFile so downstream consumers can
// always identify which manifest a result came from. Identity.Legacy is populated to bridge
// legacy CLI quirks: it carries the upstream Target bytes and signals via
// SuppressTargetFileFromPlugin which project types should suppress emission of
// MetaKeyTargetFileFromPlugin (mirrors the legacy CLI's `plugin.targetFile` presence-vs-absence
// semantic — some snyk plugins deliberately leave it unset).
func depGraphOutputToSCAResult(ctx context.Context, log logger.Logger, output *parsers.DepGraphOutput) ecosystems.SCAResult {
	result := ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile:    &output.NormalisedTargetFile,
				TargetRuntime: output.TargetRuntime,
				Legacy: &identity.LegacyIdentity{
					Target: output.Target,
				},
			},
		},
		ResolverMetadata: &ecosystems.ResolverMetadata{
			PluginName: PluginName,
		},
	}

	// If there's an error in the output, parse as ErrorCatalog so os-flows can render it
	// (expected with --print-effective-graph-with-errors). Use the first error when the
	// JSON API provides multiple — same shape as the UV plugin's per-result errors.
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
		result.ProjectDescriptor.Identity.Legacy.SuppressTargetFileFromPlugin = shouldSuppressTargetFileFromPlugin(
			dg.PkgManager.Name,
			output.NormalisedTargetFile,
			output.Workspace != nil,
		)

		if rootPkg := dg.GetRootPkg(); rootPkg != nil {
			result.ProjectDescriptor.Identity.RootComponentName = rootPkg.Info.Name
		}
	}

	return result
}
