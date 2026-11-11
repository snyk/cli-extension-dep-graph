package depgraph

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
)

func TestPipeline_SBOMAndChannelOutputsShareResolution(t *testing.T) {
	failure := errors.New("UV fixture failed")
	cases := []struct {
		name                    string
		graph, claim, empty     bool
		resultError, setupError error
		wantTargets             []string
	}{
		{name: "graph without claims stops", graph: true, wantTargets: []string{"pyproject.toml"}},
		{name: "scope claim stops", claim: true},
		{name: "empty callback continues", empty: true, wantTargets: []string{"package.json"}},
		{name: "result error stops", resultError: failure},
		{name: "setup error stops", setupError: failure},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestContext(t, false)
			tc.config.Set(workflow.FlagUseSBOMResolution, true)
			harness := NewLegacyHarness(tc)
			harness.ReturnTargets = []string{"package.json"}
			result := ecosystems.SCAResult{ResolverMetadata: &ecosystems.ResolverMetadata{
				PluginName: "uv", NormalisedTargetFile: "pyproject.toml",
			}, Error: tt.resultError}
			if tt.graph {
				result.DepGraph = createTestDepGraph(t, "uv", "python-app", "1.0.0")
			}
			if tt.claim {
				result.ProcessedFiles = []string{"uv.lock"}
			}
			if tt.empty {
				result = ecosystems.SCAResult{}
			}
			plugin := &mockScaPlugin{name: "uv", results: []ecosystems.SCAResult{result}, err: tt.setupError}
			registry, err := orchestrator.NewPluginRegistry(tc.invocationContext, orchestrator.WithUVPlugin(plugin))
			require.NoError(t, err)

			data, sbomErr := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, registry.Plugins())
			var channelResults []ecosystems.SCAResult
			for resolved := range registry.ResolveDepgraphs(".", ecosystems.NewPluginOptions()) {
				channelResults = append(channelResults, resolved)
			}

			if tt.resultError != nil || tt.setupError != nil {
				require.ErrorIs(t, sbomErr, failure)
				require.Len(t, channelResults, 1)
				require.ErrorIs(t, channelResults[0].Error, failure)
				return
			}
			require.NoError(t, sbomErr)
			var sbomTargets, channelTargets []string
			for _, item := range data {
				sbomTargets = append(sbomTargets, metaString(t, item, workflow.MetaKeyNormalisedTargetFile))
			}
			for _, resolved := range channelResults {
				if resolved.DepGraph != nil {
					channelTargets = append(channelTargets, resolved.ResolverMetadata.NormalisedTargetFile)
				}
			}
			assert.Equal(t, tt.wantTargets, sbomTargets)
			assert.Equal(t, sbomTargets, channelTargets)
		})
	}
}
