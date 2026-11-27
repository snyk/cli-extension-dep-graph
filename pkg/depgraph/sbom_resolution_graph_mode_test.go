//nolint:lll // Inlined JSON fixtures emulating the legacy CLI.
package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	dg "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
)

const (
	printGraph                  = "--print-graph"
	printEffectiveGraph         = "--print-effective-graph"
	printEffectiveGraphWithErrs = "--print-effective-graph-with-errors"
)

type graphModeCase struct {
	name  string
	flags map[string]any
	// wantArg is the graph argument SBOM resolution must hand the legacy CLI.
	wantArg string
	// beforeArg is what SBOM resolution handed it before SCAS-1054, logged
	// for the record.
	beforeArg string
	// scas1055 marks rows where, with a failing project, SBOM resolution
	// already diverges from the standard path for reasons unrelated to the
	// graph argument: it drops errored results (losing cli-extension-sbom's
	// ScanErrors) and fails a single errored project that the standard path
	// returns as data. Measured in SCAS-1055, not fixed here.
	scas1055 bool
}

// sbomCases are every depgraph configuration cli-extension-sbom's
// applyDepGraphConfig (internal/commands/sbomcreate/depgraph.go) produces:
// --all-projects sets fail-fast; --allow-incomplete-sbom clears it and sets
// print-output-jsonl-with-errors; -p asks for the effective graph only when
// the prune-effective-graph feature flag is on (with-errors under
// --allow-incomplete-sbom). It also sets the keep-caller-graph-mode key.
var sbomCases = []graphModeCase{
	{name: "no -p", flags: map[string]any{}, wantArg: printGraph, beforeArg: printEffectiveGraphWithErrs},
	{name: "-p, prune flag off", flags: map[string]any{
		workflow.FlagPruneRepeatedSubdependencies: true,
	}, wantArg: printGraph, beforeArg: printEffectiveGraphWithErrs},
	{name: "-p, prune flag on", flags: map[string]any{
		workflow.FlagPruneRepeatedSubdependencies: true, workflow.FlagPrintEffectiveGraph: true,
	}, wantArg: printEffectiveGraph, beforeArg: printEffectiveGraphWithErrs},
	{name: "--all-projects", flags: map[string]any{
		workflow.FlagAllProjects: true, workflow.FlagFailFast: true,
	}, wantArg: printGraph, beforeArg: printEffectiveGraphWithErrs},
	{name: "--all-projects, -p, prune flag off", flags: map[string]any{
		workflow.FlagAllProjects: true, workflow.FlagFailFast: true, workflow.FlagPruneRepeatedSubdependencies: true,
	}, wantArg: printGraph, beforeArg: printEffectiveGraphWithErrs},
	{name: "--all-projects, -p, prune flag on", flags: map[string]any{
		workflow.FlagAllProjects: true, workflow.FlagFailFast: true, workflow.FlagPruneRepeatedSubdependencies: true,
		workflow.FlagPrintEffectiveGraph: true,
	}, wantArg: printEffectiveGraph, beforeArg: printEffectiveGraphWithErrs},
	// The --allow-incomplete-sbom rows match on arguments, but with a failing
	// project SBOM resolution drops the errored result, so cli-extension-sbom
	// loses its ScanErrors (and a single errored project fails the run).
	// SCAS-1055 measured this; it is not fixed here.
	{name: "--allow-incomplete-sbom", flags: map[string]any{
		workflow.FlagFailFast: false, workflow.FlagPrintOutputJsonlWithErrors: true,
	}, wantArg: printGraph, beforeArg: printGraph, scas1055: true},
	{name: "--allow-incomplete-sbom, -p, prune flag off", flags: map[string]any{
		workflow.FlagFailFast: false, workflow.FlagPrintOutputJsonlWithErrors: true,
		workflow.FlagPruneRepeatedSubdependencies: true,
	}, wantArg: printGraph, beforeArg: printGraph, scas1055: true},
	{name: "--allow-incomplete-sbom, -p, prune flag on", flags: map[string]any{
		workflow.FlagFailFast: false, workflow.FlagPrintOutputJsonlWithErrors: true,
		workflow.FlagPruneRepeatedSubdependencies: true, workflow.FlagPrintEffectiveGraphWithErrors: true,
	}, wantArg: printEffectiveGraphWithErrs, beforeArg: printGraph, scas1055: true},
	{name: "--all-projects --allow-incomplete-sbom", flags: map[string]any{
		workflow.FlagAllProjects: true, workflow.FlagFailFast: false, workflow.FlagPrintOutputJsonlWithErrors: true,
	}, wantArg: printGraph, beforeArg: printGraph, scas1055: true},
	{name: "--all-projects --allow-incomplete-sbom, -p, prune flag off", flags: map[string]any{
		workflow.FlagAllProjects: true, workflow.FlagFailFast: false, workflow.FlagPrintOutputJsonlWithErrors: true,
		workflow.FlagPruneRepeatedSubdependencies: true,
	}, wantArg: printGraph, beforeArg: printGraph, scas1055: true},
	{name: "--all-projects --allow-incomplete-sbom, -p, prune flag on", flags: map[string]any{
		workflow.FlagAllProjects: true, workflow.FlagFailFast: false, workflow.FlagPrintOutputJsonlWithErrors: true,
		workflow.FlagPruneRepeatedSubdependencies: true, workflow.FlagPrintEffectiveGraphWithErrors: true,
	}, wantArg: printEffectiveGraphWithErrs, beforeArg: printGraph, scas1055: true},
}

// osFlowsCases are the configurations cli-extension-os-flows' `snyk test`
// sends into SBOM resolution (resolveViaWorkflow in internal/common/depgraph.go,
// taken when uv.lock is present and the uv feature flag is on): effective-graph
// always, plus the user's own flags. It does not set the keep-caller-graph-mode
// key, so SBOM resolution must keep forcing the effective graph with errors.
var osFlowsCases = []graphModeCase{
	{name: "snyk test", flags: map[string]any{
		workflow.FlagPrintEffectiveGraph: true,
	}, wantArg: printEffectiveGraphWithErrs, beforeArg: printEffectiveGraphWithErrs},
	{name: "snyk test -p", flags: map[string]any{
		workflow.FlagPrintEffectiveGraph: true, workflow.FlagPruneRepeatedSubdependencies: true,
	}, wantArg: printEffectiveGraphWithErrs, beforeArg: printEffectiveGraphWithErrs},
	{name: "snyk test --all-projects", flags: map[string]any{
		workflow.FlagPrintEffectiveGraph: true, workflow.FlagAllProjects: true,
	}, wantArg: printEffectiveGraphWithErrs, beforeArg: printEffectiveGraphWithErrs},
	{name: "snyk test --all-projects --fail-fast", flags: map[string]any{
		workflow.FlagPrintEffectiveGraph: true, workflow.FlagAllProjects: true, workflow.FlagFailFast: true,
	}, wantArg: printEffectiveGraphWithErrs, beforeArg: printEffectiveGraphWithErrs},
	{name: "snyk test --all-projects -p", flags: map[string]any{
		workflow.FlagPrintEffectiveGraph: true, workflow.FlagAllProjects: true, workflow.FlagPruneRepeatedSubdependencies: true,
	}, wantArg: printEffectiveGraphWithErrs, beforeArg: printEffectiveGraphWithErrs},
}

// legacyCLIEmulator answers the legacy CLI workflow the way snyk/cli's
// run-test.ts does for the arguments it was given (main 67aee31b):
//
//   - --all-projects finds package.json and sub/build.gradle; with failing,
//     pom.xml fails instead of sub/build.gradle. One project otherwise.
//   - Failed --all-projects projects are printed as JSONL error lines only
//     under --print-effective-graph-with-errors or
//     --print-output-jsonl-with-errors (run-test.ts:704-711); --fail-fast then
//     throws FailedToRunTestError (run-test.ts:713-717).
//   - A failing single project throws, unless --print-output-jsonl-with-errors
//     turns it into an error line (get-deps-from-plugin.ts:161-176).
//   - Graphs are plain text for a bare --print-graph, JSONL otherwise
//     (run-test.ts:860-873, 918-929).
type legacyCLIEmulator struct {
	failing bool
	args    [][]string
}

const (
	emulatedGraphTemplate = `{"schemaVersion":"1.3.0","pkgManager":{"name":"npm"},"pkgs":[{"id":"%[1]s@1.0.0","info":{"name":"%[1]s","version":"1.0.0"}},{"id":"lodash@4.17.21","info":{"name":"lodash","version":"4.17.21"}}],"graph":{"rootNodeId":"root-node","nodes":[{"nodeId":"root-node","pkgId":"%[1]s@1.0.0","deps":[{"nodeId":"lodash@4.17.21"}]},{"nodeId":"lodash@4.17.21","pkgId":"lodash@4.17.21","deps":[]}]}}`
	emulatedErrorLine     = `{"normalisedTargetFile":"pom.xml","error":{"jsonapi":{"version":"1.0"},"errors":[{"id":"x","status":"422","code":"SNYK-OS-MAVEN-0001","title":"Maven failed","detail":"mvn exited 1","meta":{"isErrorCatalogError":true,"classification":"ACTIONABLE"}}]}}`
	emulatedCLIJSONError  = `{"ok":false,"error":"Your test request could not be completed.","path":"."}`
)

func newLegacyCLIEmulator(tc *testContext, failing bool) *legacyCLIEmulator {
	e := &legacyCLIEmulator{failing: failing}
	tc.engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ gafworkflow.Identifier, cfg configuration.Configuration) ([]gafworkflow.Data, error) {
			args := cfg.GetStringSlice(configuration.RAW_CMD_ARGS)
			e.args = append(e.args, args)
			return e.respond(args)
		}).
		AnyTimes()
	return e
}

func (e *legacyCLIEmulator) respond(args []string) ([]gafworkflow.Data, error) {
	has := func(a string) bool { return slices.Contains(args, a) }
	allProjects, jsonlErrs := has("--all-projects"), has("--print-output-jsonl-with-errors")

	good := []string{"package.json"}
	if allProjects {
		good = append(good, "sub/build.gradle")
	}
	if e.failing {
		good = good[:len(good)-1]
	}

	var out strings.Builder
	if e.failing {
		if !allProjects && !jsonlErrs {
			return payload(emulatedCLIJSONError), mockExitError{code: 2}
		}
		if jsonlErrs || has(printEffectiveGraphWithErrs) {
			out.WriteString(emulatedErrorLine + "\n")
		}
		if allProjects && has("--fail-fast") {
			out.WriteString(emulatedCLIJSONError + "\n")
			return payload(out.String()), mockExitError{code: 2}
		}
	}
	for _, target := range good {
		graph := fmt.Sprintf(emulatedGraphTemplate, strings.ReplaceAll(target, "/", "-"))
		if has(printGraph) && !jsonlErrs {
			fmt.Fprintf(&out, "DepGraph data:\n%s\nDepGraph target:\n%s\nDepGraph end\n\n", graph, target)
			continue
		}
		fmt.Fprintf(&out, `{"depGraph":%s,"normalisedTargetFile":%q,"targetFileFromPlugin":%q,"target":{}}`+"\n", graph, target, target)
	}
	return payload(out.String()), nil
}

func payload(body string) []gafworkflow.Data {
	return []gafworkflow.Data{gafworkflow.NewData(
		gafworkflow.NewTypeIdentifier(gafworkflow.NewWorkflowIdentifier("legacycli"), "application/text"),
		"application/text",
		[]byte(body),
	)}
}

func (e *legacyCLIEmulator) onlyCall(t *testing.T) []string {
	t.Helper()
	require.Len(t, e.args, 1, "expected exactly one legacy CLI invocation")
	return e.args[0]
}

// graphArg is the graph argument in RAW_CMD_ARGS ("test --json <graph argument> ...").
func graphArg(t *testing.T, args []string) string {
	t.Helper()
	require.GreaterOrEqual(t, len(args), 3)
	return args[2]
}

// outcome is what a caller of the depgraph workflow can observe.
type outcome struct {
	args      []string
	errCode   string
	errDetail string
	exitCode  int
	message   string
	failed    bool
	graphs    []dg.DepGraph
	locations []string
	warnings  int
}

func observe(t *testing.T, cli *legacyCLIEmulator, data []gafworkflow.Data, err error, warnings int) outcome {
	t.Helper()
	o := outcome{args: cli.onlyCall(t), failed: err != nil, warnings: warnings}
	var snykErr snyk_errors.Error
	if errors.As(err, &snykErr) {
		o.errCode, o.errDetail = snykErr.ErrorCode, snykErr.Detail
	} else if err != nil {
		o.message = err.Error()
	}
	var exitCoder legacycli.ExitCoder
	if errors.As(err, &exitCoder) {
		o.exitCode = exitCoder.ExitCode()
	}
	for _, d := range data {
		// Error-only data is the standard path's way of reporting a failed
		// project; SBOM resolution drops those (SCAS-1055).
		if len(d.GetErrorList()) > 0 {
			continue
		}
		raw, ok := d.GetPayload().([]byte)
		require.True(t, ok)
		var g dg.DepGraph
		require.NoError(t, json.Unmarshal(raw, &g))
		o.graphs = append(o.graphs, g)
		o.locations = append(o.locations, d.GetContentLocation())
	}
	return o
}

func countWarnings(tc *testContext) *int {
	n := 0
	tc.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(error, ...any) error {
		n++
		return nil
	}).AnyTimes()
	return &n
}

func applyFlags(cfg configuration.Configuration, flags map[string]any) {
	for k, v := range flags {
		cfg.Set(k, v)
	}
}

// runSBOMResolution runs SBOM resolution over just the legacy plugin.
// production selects the plugin buildSCAPlugins builds; otherwise the
// plugin is built the way it was before SCAS-1054 (always forcing).
func runSBOMResolution(t *testing.T, flags map[string]any, failing, production bool) outcome {
	t.Helper()
	tc := setupTestContext(t, false)
	warnings := countWarnings(tc)
	cli := newLegacyCLIEmulator(tc, failing)
	applyFlags(tc.config, flags)

	var plugin ecosystems.SCAPlugin = legacy.NewPlugin(tc.invocationContext)
	if production {
		plugins, err := buildSCAPlugins(tc.invocationContext, nil, "")
		require.NoError(t, err)
		plugin = plugins[len(plugins)-1]
		require.Equal(t, legacy.PluginName, plugin.GetName())
	}
	data, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, []ecosystems.SCAPlugin{plugin})
	return observe(t, cli, data, err, *warnings)
}

func runStandardPath(t *testing.T, flags map[string]any, failing bool) outcome {
	t.Helper()
	tc := setupTestContext(t, false)
	warnings := countWarnings(tc)
	cli := newLegacyCLIEmulator(tc, failing)
	cfg := configuration.New()
	applyFlags(cfg, flags)
	data, err := legacycli.HandleLegacyResolution(tc.invocationContext, cfg, &nopLogger)
	return observe(t, cli, data, err, *warnings)
}

// withInputDir returns flags plus a fresh input directory, so every path
// run for a row scans the same directory.
func withInputDir(t *testing.T, flags map[string]any, extra ...map[string]any) map[string]any {
	t.Helper()
	out := map[string]any{configuration.INPUT_DIRECTORY: t.TempDir()}
	for _, m := range append([]map[string]any{flags}, extra...) {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

var keepCallerGraphMode = map[string]any{ConfigKeyKeepCallerGraphMode: true}

// dropDir removes the input directory, for readable logs.
func dropDir(args []string) []string {
	return slices.DeleteFunc(slices.Clone(args), func(a string) bool { return strings.HasPrefix(a, "/") })
}

// Test_legacyGraphMode_sbomMatchesStandardPath pins SCAS-1054: for a project
// left to the legacy CLI, `snyk sbom` through SBOM resolution must invoke the
// legacy CLI exactly as the standard depgraph path (HandleLegacyResolution,
// what `snyk sbom` uses today) does, and so get the same graphs, error-catalog
// codes and exit codes. It does not compare messages of errors outside the
// catalog: SBOM resolution wraps those ("error building results: ..."), so
// the text differs while the exit code is the same.
func Test_legacyGraphMode_sbomMatchesStandardPath(t *testing.T) {
	for _, tt := range sbomCases {
		for _, failing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failing=%t", tt.name, failing), func(t *testing.T) {
				flags := withInputDir(t, tt.flags, keepCallerGraphMode)
				standard := runStandardPath(t, flags, failing)
				sbom := runSBOMResolution(t, flags, failing, true)
				t.Logf("before: %s  standard: %v  sbom: %v", tt.beforeArg, dropDir(standard.args), dropDir(sbom.args))

				assert.Equal(t, standard.args, sbom.args, "SBOM resolution must invoke the legacy CLI exactly as the standard path does")
				assert.Equal(t, tt.wantArg, graphArg(t, sbom.args))

				if failing && tt.scas1055 {
					return
				}
				assert.Equal(t, standard.failed, sbom.failed, "same success or failure")
				assert.Equal(t, standard.errCode, sbom.errCode)
				assert.Equal(t, standard.errDetail, sbom.errDetail)
				assert.Equal(t, standard.exitCode, sbom.exitCode, "same exit code")
				assert.Equal(t, standard.locations, sbom.locations, "same projects, in the same order")
				assert.Equal(t, standard.graphs, sbom.graphs)
			})
		}
	}
}

// Test_legacyGraphMode_osFlowsUnchanged pins that `snyk test` from
// cli-extension-os-flows, which enters SBOM resolution for uv repos, still
// gets the forced effective graph with errors: same arguments, errors,
// warnings and graphs as before SCAS-1054.
func Test_legacyGraphMode_osFlowsUnchanged(t *testing.T) {
	for _, tt := range osFlowsCases {
		for _, failing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failing=%t", tt.name, failing), func(t *testing.T) {
				flags := withInputDir(t, tt.flags)
				before := runSBOMResolution(t, flags, failing, false)
				after := runSBOMResolution(t, flags, failing, true)
				t.Logf("before: %v  after: %v", dropDir(before.args), dropDir(after.args))

				assert.Equal(t, tt.wantArg, graphArg(t, after.args))
				assert.Equal(t, before, after)
			})
		}
	}
}

// Test_legacyGraphMode_registryKeepsEffectiveGraphWithErrors pins that the
// orchestrator registry (`snyk test` via cli-extension-os-flows when it does
// not enter SBOM resolution) still forces the effective graph with errors,
// whatever the caller's flags, unless the caller asked for JSONL with errors.
func Test_legacyGraphMode_registryKeepsEffectiveGraphWithErrors(t *testing.T) {
	cases := append(slices.Clone(osFlowsCases),
		graphModeCase{name: "caller asks for the raw graph", flags: map[string]any{}, wantArg: printEffectiveGraphWithErrs},
		graphModeCase{name: "caller asks for JSONL with errors", flags: map[string]any{
			workflow.FlagPrintOutputJsonlWithErrors: true,
		}, wantArg: printGraph},
		graphModeCase{name: "caller sets the keep-caller-graph-mode key", flags: map[string]any{
			ConfigKeyKeepCallerGraphMode: true, workflow.FlagPrintEffectiveGraph: true,
		}, wantArg: printEffectiveGraphWithErrs},
	)
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestContext(t, true)
			cli := newLegacyCLIEmulator(tc, false)
			flags := withInputDir(t, tt.flags)
			applyFlags(tc.config, flags)
			dir := tc.config.GetString(configuration.INPUT_DIRECTORY)
			registry, err := orchestrator.NewDefaultPluginRegistry(tc.invocationContext)
			require.NoError(t, err)

			opts := ecosystems.NewPluginOptions().WithAllProjects(tc.config.GetBool(workflow.FlagAllProjects))
			locations := make([]string, 0, 2)
			for result := range registry.ResolveDepgraphs(dir, opts) {
				require.NoError(t, result.Error)
				locations = append(locations, result.ResolverMetadata.NormalisedTargetFile)
			}

			assert.Equal(t, tt.wantArg, graphArg(t, cli.onlyCall(t)))
			want := []string{"package.json"}
			if tc.config.GetBool(workflow.FlagAllProjects) {
				want = append(want, "sub/build.gradle")
			}
			assert.Equal(t, want, locations)
		})
	}
}

// Test_legacyHarness_callerMode_errorsAndWarnings re-runs the legacy-harness
// error and warning scenarios with the keep-caller-graph-mode key set, so the
// SBOM-resolution error handling is exercised with the plugin `snyk sbom`
// gets in production, not only the forcing default.
func Test_legacyHarness_callerMode_errorsAndWarnings(t *testing.T) {
	errorLines := []string{
		MakeLegacyJSONLLine("legacy-project/valid.json"),
		MakeLegacyJSONLLineWithErrorCatalog("legacy-project/requirements.txt", "SNYK-LEGACY-001", "Legacy Error Title", "Detailed legacy error information"),
	}
	newHarness := func(t *testing.T, withDefaultUI bool, flags map[string]any) (*testContext, *LegacyHarness) {
		t.Helper()
		tc := setupTestContext(t, withDefaultUI)
		applyFlags(tc.config, withInputDir(t, flags, keepCallerGraphMode))
		return tc, NewLegacyHarness(tc)
	}

	t.Run("--all-projects --allow-incomplete-sbom: errored project becomes a warning", func(t *testing.T) {
		tc, h := newHarness(t, false, map[string]any{workflow.FlagAllProjects: true, workflow.FlagPrintOutputJsonlWithErrors: true})
		h.ReturnLines = errorLines
		var warning string
		tc.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...any) error {
			warning = err.Error()
			return nil
		}).Times(1)

		data, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, []ecosystems.SCAPlugin{h.Plugin})

		require.NoError(t, err)
		assert.Equal(t, printGraph, graphArg(t, h.capturedCfg.GetStringSlice(configuration.RAW_CMD_ARGS)))
		require.Len(t, data, 1, "only the valid project is returned; the errored one is dropped (SCAS-1055)")
		assert.Equal(t, "legacy-project/valid.json", data[0].GetContentLocation())
		assert.Contains(t, warning, "Detailed legacy error information")
		assert.Contains(t, warning, "1/2 potential projects failed to get dependencies")
	})

	t.Run("--all-projects --fail-fast with JSONL errors: halts with exit code 2", func(t *testing.T) {
		tc, h := newHarness(t, true, map[string]any{
			workflow.FlagAllProjects: true, workflow.FlagFailFast: true, workflow.FlagPrintOutputJsonlWithErrors: true,
		})
		h.ReturnLines = errorLines

		_, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, []ecosystems.SCAPlugin{h.Plugin})

		require.Error(t, err)
		var ec legacycli.ExitCoder
		require.True(t, errors.As(err, &ec))
		assert.Equal(t, 2, ec.ExitCode())
	})

	t.Run("--all-projects, legacy CLI fails: run fails with the CLI's error", func(t *testing.T) {
		tc, h := newHarness(t, true, map[string]any{workflow.FlagAllProjects: true, workflow.FlagFailFast: true})
		h.ReturnError = mockExitError{code: 2}

		_, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, []ecosystems.SCAPlugin{h.Plugin})

		require.Error(t, err)
		assert.Equal(t, printGraph, graphArg(t, h.capturedCfg.GetStringSlice(configuration.RAW_CMD_ARGS)))
		var snykErr snyk_errors.Error
		assert.True(t, errors.As(err, &snykErr), "the CLI failure surfaces as a catalog error")
	})

	t.Run("--all-projects, raw graph: plain-text projects are returned in order", func(t *testing.T) {
		tc, h := newHarness(t, true, map[string]any{workflow.FlagAllProjects: true, workflow.FlagFailFast: true})
		h.ReturnTargets = []string{"package.json", "sub/package.json"}

		data, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, []ecosystems.SCAPlugin{h.Plugin})

		require.NoError(t, err)
		locations := make([]string, len(data))
		for i, d := range data {
			locations[i] = d.GetContentLocation()
		}
		assert.Equal(t, []string{"package.json", "sub/package.json"}, locations)
	})
}
