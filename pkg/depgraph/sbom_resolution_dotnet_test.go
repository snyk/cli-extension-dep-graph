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

// metaString reads one metadata value off a workflow.Data.
func metaString(t *testing.T, data gafworkflow.Data, key string) string {
	t.Helper()

	value, err := data.GetMetaData(key)
	require.NoError(t, err, "metadata %q should be set", key)

	return value
}

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

// sdkStyleProject writes a restored SDK-style project — the shape the .NET
// resolver claims.
func sdkStyleProject(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "obj", "project.assets.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(`{
      "version": 3,
      "targets": { "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } } },
      "projectFileDependencyGroups": { "net8.0": [ "Newtonsoft.Json >= 13.0.3" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": { "targetAlias": "net8.0" } } }
    }`), 0o600))

	return dir
}

// frameworkProject writes a .NET Framework project — the shape the .NET
// resolver declines, so that it falls back to the legacy one.
func frameworkProject(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"), []byte(""), 0o600))

	return dir
}

// Test_handleSBOMResolution_dotnetResolver drives the SBOM resolution flow over
// real .NET project directories, pinning down what the feature flag changes for
// each kind of project.
func Test_handleSBOMResolution_dotnetResolver(t *testing.T) {
	// run drives the flow with the plugin list production would assemble.
	run := func(t *testing.T, inputDir string, dotnetEnabled, allProjects bool, legacyTargets []string) ([]gafworkflow.Data, *LegacyHarness) {
		t.Helper()

		tc := setupTestContext(t, true)
		harness := NewLegacyHarness(tc)
		harness.ReturnTargets = legacyTargets

		tc.config.Set(configuration.INPUT_DIRECTORY, inputDir)
		tc.config.Set(workflow.FlagAllProjects, allProjects)
		if dotnetEnabled {
			tc.config.Set(orchestrator.FlagDotnetResolver.Key, true)
		}

		plugins := buildSCAPlugins(tc.invocationContext, tc.config, nil, "")

		workflowData, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, plugins)
		require.NoError(t, err)

		return workflowData, harness
	}

	// assertResolvedGraph checks data carries the graph the .NET resolver built.
	assertResolvedGraph := func(t *testing.T, data gafworkflow.Data) {
		t.Helper()

		payload, ok := data.GetPayload().([]byte)
		require.True(t, ok, "payload should be []byte")

		graph, err := dg.UnmarshalJSON(payload)
		require.NoError(t, err)
		assert.Equal(t, "nuget", graph.PkgManager.Name)
		assert.NotEmpty(t, graph.GetRootPkg().Info.Name, "the root is named after the project directory")
		assert.Equal(t, "1.0.0", graph.GetRootPkg().Info.Version, "taken from project.version")
		assert.Len(t, graph.Pkgs, 2, "the root plus its one dependency")
	}

	// The runtime is the only thing separating the graphs a multi-targeting
	// project resolves to, so it has to reach the workflow data or those graphs
	// are indistinguishable to everything downstream.
	t.Run("flag on: each graph carries its target runtime", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "obj", "project.assets.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(`{
          "version": 3,
          "targets": {
            "net6.0": { "Newtonsoft.Json/13.0.1": { "type": "package" } },
            "net8.0": { "Newtonsoft.Json/13.0.3": { "type": "package" } }
          },
          "projectFileDependencyGroups": {
            "net6.0": [ "Newtonsoft.Json >= 13.0.1" ],
            "net8.0": [ "Newtonsoft.Json >= 13.0.1" ]
          },
          "project": {
            "version": "1.0.0",
            "frameworks": {
              "net6.0": { "targetAlias": "net6.0" },
              "net8.0": { "targetAlias": "net8.0" }
            }
          }
        }`), 0o600))

		workflowData, _ := run(t, dir, true, true, nil)
		require.Len(t, workflowData, 2)

		runtimes := make([]string, 0, len(workflowData))
		for _, data := range workflowData {
			// Both graphs share a target file, so this is the disambiguator.
			assert.Equal(t, filepath.Join("obj", "project.assets.json"),
				metaString(t, data, workflow.MetaKeyNormalisedTargetFile))

			runtimes = append(runtimes, metaString(t, data, workflow.MetaKeyTargetRuntime))
		}

		assert.Equal(t, []string{"net6.0", "net8.0"}, runtimes)
	})

	t.Run("flag off leaves the legacy result untouched", func(t *testing.T) {
		workflowData, harness := run(t, sdkStyleProject(t), false, false, []string{"obj/project.assets.json"})

		assert.True(t, harness.Called(), "the legacy resolver still handles .NET projects")
		assert.Len(t, workflowData, 1, "no extra dep graph is produced")
	})

	t.Run("flag on: the resolver handles an SDK-style project", func(t *testing.T) {
		workflowData, harness := run(t, sdkStyleProject(t), true, false, []string{"obj/project.assets.json"})

		assert.False(t, harness.Called(),
			"the loop stops once a plugin returns results, so legacy never runs")
		require.Len(t, workflowData, 1)
		assertResolvedGraph(t, workflowData[0])
	})

	// Claiming the file is what keeps --all-projects from reporting the project
	// twice: the claim reaches the legacy resolver as --exclude-paths. The legacy
	// harness is given a result of its own so that "one graph" is a real
	// observation rather than the mock simply having nothing to say.
	t.Run("flag on with --all-projects: the project is claimed, not duplicated", func(t *testing.T) {
		workflowData, harness := run(t, sdkStyleProject(t), true, true, []string{"package.json"})

		require.True(t, harness.Called(), "the legacy resolver still runs, for the other ecosystems")
		require.Len(t, workflowData, 2, "our .NET graph plus the legacy result for another ecosystem")
		assertResolvedGraph(t, workflowData[0])

		assert.Equal(t, filepath.Join("obj", "project.assets.json"), harness.CapturedExcludePaths(),
			"exactly the resolved project is excluded from the legacy scan, by relative path")
	})

	// A mixed repo is the shape that would break first if the claim were ever
	// widened from a file to its directory, or if ExcludePaths went from append
	// to overwrite: the packages.config project would silently vanish.
	t.Run("flag on with --all-projects: a mixed repo keeps both projects", func(t *testing.T) {
		dir := sdkStyleProject(t)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "packages.config"), []byte(""), 0o600))

		workflowData, harness := run(t, dir, true, true, []string{"packages.config"})

		require.True(t, harness.Called())
		require.Len(t, workflowData, 2, "ours for the SDK-style project, legacy's for packages.config")
		assertResolvedGraph(t, workflowData[0])

		assert.NotContains(t, harness.CapturedExcludePaths(), "packages.config",
			"the project we did not resolve must not be excluded from the legacy scan")
	})

	// An assets file we cannot use must not be claimed, or the resolver that
	// could still handle it is told to skip it.
	t.Run("flag on: an unusable assets file falls back to legacy", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "obj", "project.assets.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte("{ not json"), 0o600))

		workflowData, harness := run(t, dir, true, false, []string{"obj/project.assets.json"})

		assert.True(t, harness.Called(), "the legacy resolver must still get a chance at it")
		require.Len(t, workflowData, 1, "and its result is the only one")
		assert.Empty(t, harness.CapturedExcludePaths(), "nothing was claimed from under it")
	})

	// A .NET project this resolver does not support must reach the legacy one
	// even for a single project, which only works because the plugin returns no
	// results at all rather than an empty graph.
	t.Run("flag on: a packages.config project falls back to legacy", func(t *testing.T) {
		workflowData, harness := run(t, frameworkProject(t), true, false, []string{"packages.config"})

		assert.True(t, harness.Called(), "the legacy resolver must still handle it")
		require.Len(t, workflowData, 1, "and its result is the only one")
		assert.Empty(t, harness.CapturedExcludePaths(), "nothing was claimed from under it")
	})
}
