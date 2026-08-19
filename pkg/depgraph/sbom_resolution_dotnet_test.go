package depgraph

import (
	"os"
	"path/filepath"
	"testing"

	dg "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
)

// pluginNames lists the assembled plugins in the order they will run.
func pluginNames(plugins []ecosystems.SCAPlugin) []string {
	names := make([]string, len(plugins))
	for i, p := range plugins {
		names[i] = p.GetName()
	}

	return names
}

func Test_buildSCAPlugins_dotnetResolverIsOptIn(t *testing.T) {
	tc := setupTestContext(t, false)

	plugins := buildSCAPlugins(tc.invocationContext, tc.config, nil, "")

	assert.Equal(t, []string{"uv", "legacycli"}, pluginNames(plugins),
		"the .NET resolver must not run unless its feature flag is set")
}

func Test_buildSCAPlugins_dotnetResolverEnabled(t *testing.T) {
	tc := setupTestContext(t, false)
	tc.config.Set(orchestrator.FlagDotnetResolver.Key, true)

	plugins := buildSCAPlugins(tc.invocationContext, tc.config, nil, "")

	// legacy stays last: it is the fallback, and each plugin's processed files
	// are excluded from the plugins that follow it.
	require.Equal(t, []string{"uv", "dotnet", "legacycli"}, pluginNames(plugins))
}

// Test_handleSBOMResolution_dotnetResolver drives the SBOM resolution flow over a
// real .NET project directory, pinning down what the feature flag actually
// changes in each scan mode.
//
// Note the asymmetry, which comes from handleSBOMResolutionDI breaking out of
// the plugin loop after the first plugin to return any results unless
// --all-projects is set. Declining to claim ProcessedFiles keeps the placeholder
// additive under --all-projects, but cannot keep it additive for a single
// project: there, the first plugin with results wins outright.
func Test_handleSBOMResolution_dotnetResolver(t *testing.T) {
	newFixtureDir := func(t *testing.T) string {
		t.Helper()

		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"), []byte(""), 0o600))

		return dir
	}

	// run drives the flow with the plugin list production would assemble.
	run := func(t *testing.T, dotnetEnabled, allProjects bool) ([]gafworkflow.Data, *LegacyHarness) {
		t.Helper()

		tc := setupTestContext(t, true)
		harness := NewLegacyHarness(tc)
		harness.ReturnTargets = []string{"packages.config"}

		tc.config.Set(configuration.INPUT_DIRECTORY, newFixtureDir(t))
		tc.config.Set(workflow.FlagAllProjects, allProjects)
		if dotnetEnabled {
			tc.config.Set(orchestrator.FlagDotnetResolver.Key, true)
		}

		plugins := buildSCAPlugins(tc.invocationContext, tc.config, nil, "")

		workflowData, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, plugins)
		require.NoError(t, err)

		return workflowData, harness
	}

	// assertPlaceholderGraph checks data carries the placeholder .NET dep graph.
	assertPlaceholderGraph := func(t *testing.T, data gafworkflow.Data) {
		t.Helper()

		payload, ok := data.GetPayload().([]byte)
		require.True(t, ok, "payload should be []byte")

		graph, err := dg.UnmarshalJSON(payload)
		require.NoError(t, err, "the placeholder graph must be well-formed")
		assert.Equal(t, "nuget", graph.PkgManager.Name)
		assert.NotEmpty(t, graph.GetRootPkg().Info.Name, "root is named after the project directory")
		assert.Equal(t, "0.0.0", graph.GetRootPkg().Info.Version)
		assert.Len(t, graph.Pkgs, 1, "the placeholder graph reports no dependencies")
	}

	t.Run("flag off leaves the legacy result untouched", func(t *testing.T) {
		workflowData, harness := run(t, false, false)

		assert.True(t, harness.Called(), "the legacy resolver still handles .NET projects")
		assert.Len(t, workflowData, 1, "no extra dep graph is produced")
	})

	t.Run("flag on, single project: the placeholder displaces the legacy result", func(t *testing.T) {
		workflowData, harness := run(t, true, false)

		assert.False(t, harness.Called(),
			"the loop breaks after the placeholder returns results, so legacy never runs")
		require.Len(t, workflowData, 1)
		assertPlaceholderGraph(t, workflowData[0])
	})

	t.Run("flag on with --all-projects: placeholder is additive", func(t *testing.T) {
		workflowData, harness := run(t, true, true)

		// No break in --all-projects mode, and the placeholder claims no
		// ProcessedFiles, so the legacy resolver still reports the project.
		assert.True(t, harness.Called(), "the legacy resolver must not be skipped")
		require.Len(t, workflowData, 2)
		assertPlaceholderGraph(t, workflowData[0])
	})
}
