package depgraph

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	dg "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/python/uv"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

//go:embed testdata/uv-sbom-convert-expected-dep-graph.json
var uvSBOMConvertExpectedDepGraph string

//go:embed testdata/uv-sbom-convert-response.json
var uvSBOMConvertResponse string

// mockScaPlugin emits a configured set of SCAResults through the
// SCAPlugin callback contract. Each result carries its own
// ProcessedFiles list (the per-graph attribution downstream consumers
// rely on).
type mockScaPlugin struct {
	name    string
	results []ecosystems.SCAResult
	err     error
	options *ecosystems.SCAPluginOptions
}

func (m *mockScaPlugin) GetName() string {
	return m.name
}

func (m *mockScaPlugin) BuildDepGraphsFromDir(
	_ context.Context,
	_ logger.Logger,
	_ string,
	options *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	m.options = options
	if m.err != nil {
		return m.err
	}
	for _, r := range m.results {
		if err := onGraph(r); err != nil {
			return err
		}
	}
	return nil
}

// withProcessedFiles returns r with ProcessedFiles set, for use in
// fixture literals where attaching the file list to a SCAResult
// inline keeps the test data dense.
func withProcessedFiles(r ecosystems.SCAResult, files ...string) ecosystems.SCAResult {
	r.ProcessedFiles = files
	return r
}

// LegacyHarness wraps a real `legacy.Plugin` whose underlying `legacycli` workflow is
// answered by a mock engine. Tests construct it, optionally configure ReturnTargets /
// ReturnLines / ReturnError after construction, and pass `Plugin` into
// handleSBOMResolutionDI's scaPlugins list. At invocation time the harness records the
// cloned configuration the real `buildLegacyConfig` produced — so tests can assert on
// exactly the `--exclude-paths` / `--exclude` value the legacy CLI would have received,
// with no test-side simulation of production logic.
type LegacyHarness struct {
	Plugin ecosystems.SCAPlugin

	// ReturnTargets — if non-empty — yields one minimal JSONL line per entry, with that
	// string as `normalisedTargetFile`. Use this when a test only cares about how many
	// legacy results came back and which targets they had.
	ReturnTargets []string
	// ReturnLines — if non-empty — overrides ReturnTargets and is emitted as the raw JSONL
	// payload (one element per line). Use this when a test needs control over the line shape
	// (errors, depGraph contents, custom target metadata).
	ReturnLines []string
	// ReturnError — if non-nil — is returned from the engine call instead of any payload.
	ReturnError error

	invoked     bool
	capturedCfg configuration.Configuration
}

// NewLegacyHarness wires `ctx.engine.InvokeWithConfig` to read from the harness's
// Return* fields at invocation time and returns a harness wrapping a real legacy plugin.
// Pass `harness.Plugin` into the scaPlugins list under test.
func NewLegacyHarness(ctx *testContext) *LegacyHarness {
	h := &LegacyHarness{
		Plugin: legacy.NewPlugin(ctx.invocationContext),
	}

	ctx.engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ gafworkflow.Identifier, cfg configuration.Configuration) ([]gafworkflow.Data, error) {
			h.invoked = true
			h.capturedCfg = cfg
			if h.ReturnError != nil {
				return nil, h.ReturnError
			}

			payload := h.buildPayload()
			if payload == "" {
				return []gafworkflow.Data{}, nil
			}
			data := gafworkflow.NewData(
				gafworkflow.NewTypeIdentifier(
					gafworkflow.NewWorkflowIdentifier("legacycli"),
					"application/text"),
				"application/text",
				[]byte(payload))
			return []gafworkflow.Data{data}, nil
		}).
		AnyTimes()

	return h
}

// buildPayload turns the harness's configured Return* values into a JSONL payload.
// ReturnLines wins if both are set.
func (h *LegacyHarness) buildPayload() string {
	if len(h.ReturnLines) > 0 {
		return strings.Join(h.ReturnLines, "\n")
	}
	if len(h.ReturnTargets) == 0 {
		return ""
	}
	lines := make([]string, 0, len(h.ReturnTargets))
	for _, tf := range h.ReturnTargets {
		lines = append(lines, MakeLegacyJSONLLine(tf))
	}
	return strings.Join(lines, "\n")
}

// Called reports whether the legacy plugin actually invoked the legacy CLI workflow
// during the test.
func (h *LegacyHarness) Called() bool { return h.invoked }

// CapturedExclude returns the value of FlagExclude on the cloned config the real
// legacy plugin handed to the legacy CLI. Returns "" if the plugin was never invoked.
func (h *LegacyHarness) CapturedExclude() string {
	if h.capturedCfg == nil {
		return ""
	}
	return h.capturedCfg.GetString(workflow.FlagExclude)
}

// CapturedExcludePaths returns the value of FlagExcludePaths on the cloned config the
// real legacy plugin handed to the legacy CLI — i.e. exactly what the legacy CLI would
// have received as `--exclude-paths`. Returns "" if the plugin was never invoked.
func (h *LegacyHarness) CapturedExcludePaths() string {
	if h.capturedCfg == nil {
		return ""
	}
	return h.capturedCfg.GetString(workflow.FlagExcludePaths)
}

// MakeLegacyJSONLLine builds a single minimal JSONL line shaped like the legacy CLI's
// `--print-effective-graph-with-errors` output, with the supplied `normalisedTargetFile`.
// For tests needing per-line errors or custom shapes, build the line by hand.
func MakeLegacyJSONLLine(targetFile string) string {
	return fmt.Sprintf(
		`{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":%q,"target":{}}`,
		targetFile,
	)
}

// MakeLegacyJSONLLineWithErrorCatalog builds a JSONL line with both a depgraph and a
// JSONAPI-shaped error catalog payload — mirrors what the legacy CLI emits when
// `--print-effective-graph-with-errors` produces a partial result for a failing target.
func MakeLegacyJSONLLineWithErrorCatalog(targetFile, errorID, errorTitle, errorDetail string) string {
	return fmt.Sprintf(
		`{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":%q,"target":{},`+
			`"error":{"jsonapi":{"version":"1.0"},"errors":[{"id":%q,"title":%q,"detail":%q,`+
			`"meta":{"isErrorCatalogError":true,"classification":"ACTIONABLE"}}]}}`,
		targetFile, errorID, errorTitle, errorDetail,
	)
}

// mockExitError creates an error with the specified exit code.
type mockExitError struct {
	code int
}

func (e mockExitError) Error() string {
	return fmt.Sprintf("mock exit error: %d", e.code)
}

func (e mockExitError) ExitCode() int {
	return e.code
}

var nopLogger = zerolog.Nop()

func createTestDepGraph(t *testing.T, pkgManager, name, version string) *dg.DepGraph {
	t.Helper()
	builder, err := dg.NewBuilder(
		&dg.PkgManager{Name: pkgManager},
		&dg.PkgInfo{Name: name, Version: version},
	)
	require.NoError(t, err)
	return builder.Build()
}

// Helper struct to hold common test dependencies.
type testContext struct {
	ctrl              *gomock.Controller
	config            configuration.Configuration
	invocationContext *gafmocks.MockInvocationContext
	engine            *gafmocks.MockEngine
	userInterface     *gafmocks.MockUserInterface
}

// setupTestContext initializes common test objects and handles cleanup automatically.
//
// The mock engine is registered on the invocation context with no default behavior;
// tests that exercise the real legacy plugin should attach a `LegacyHarness` (which
// configures the engine to return canned JSONL or an error). Tests that never trigger
// the legacy plugin pay nothing for the engine mock — gomock does not require unused
// EXPECTs.
func setupTestContext(t *testing.T, withDefaultUI bool) *testContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	config := configuration.New()
	config.Set(workflow.FlagUseSBOMResolution, true)
	config.Set(configuration.ORGANIZATION, "test-org-id")

	invocationContext := gafmocks.NewMockInvocationContext(ctrl)
	invocationContext.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()
	invocationContext.EXPECT().Context().Return(context.Background()).AnyTimes()
	invocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()

	engine := gafmocks.NewMockEngine(ctrl)
	invocationContext.EXPECT().GetEngine().Return(engine).AnyTimes()

	mockUI := gafmocks.NewMockUserInterface(ctrl)
	invocationContext.EXPECT().GetUserInterface().Return(mockUI).AnyTimes()
	if withDefaultUI {
		mockUI.EXPECT().OutputError(gomock.Any()).Return(nil).AnyTimes()
	}

	return &testContext{
		ctrl:              ctrl,
		config:            config,
		invocationContext: invocationContext,
		engine:            engine,
		userInterface:     mockUI,
	}
}

func createMockSBOMService(t *testing.T, responseBody string) *httptest.Server {
	t.Helper()

	mockResponse := mocks.NewMockResponse(
		"application/json",
		[]byte(responseBody),
		http.StatusOK,
	)

	mockSBOMService := mocks.NewMockSBOMService(mockResponse, func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.RequestURI, "/hidden/orgs/test-org-id/sboms/convert")
		assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
	})
	t.Cleanup(func() { mockSBOMService.Close() })

	return mockSBOMService
}

func Test_callback_SBOMResolution(t *testing.T) {
	t.Run("should return depgraphs from SBOM conversion when use-sbom-resolution flag is enabled", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		builder, err := dg.NewBuilder(
			&dg.PkgManager{Name: "uv"},
			&dg.PkgInfo{Name: "test-pkg", Version: "1.0.0"},
		)
		require.NoError(t, err)
		expectedDepGraph := builder.Build()

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: expectedDepGraph,
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 1)
		assert.False(t, legacyMock.Called(), "legacy plugin should not be called")

		depGraph, ok := workflowData[0].GetPayload().([]byte)
		require.True(t, ok, "payload should be []byte")
		assert.JSONEq(t, uvSBOMConvertExpectedDepGraph, string(depGraph))
	})

	t.Run("should handle UV client errors gracefully", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)

		mockPlugin := &mockScaPlugin{
			err: fmt.Errorf("uv command failed"),
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "uv command failed")
		assert.Nil(t, workflowData)
		assert.False(t, legacyMock.Called(), "legacy plugin should not be called")
	})

	t.Run("should handle SBOM convert network request errors", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)

		mockPlugin := &mockScaPlugin{
			err: fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "analysis of SBOM document failed due to error")
		assert.Contains(t, err.Error(), "500")
		assert.Nil(t, workflowData)
		assert.False(t, legacyMock.Called(), "legacy plugin should not be called")
	})

	t.Run("should skip findings with errors and only process valid findings when allProjects is true", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
				{
					Error: fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "uv.lock",
					},
				},
			},
		}

		legacyMock.ReturnTargets = []string{"legacy-target/package.json"}

		depGraphs, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, depGraphs)
		assert.Len(t, depGraphs, 2, "Should return one valid finding plus legacy workflow result")
		assert.True(t, legacyMock.Called(), "legacy plugin should be called when allProjects is true")
	})

	t.Run("should return error when SBOM conversion fails for all findings when multiple findings are present", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)

		// Create mock plugin that returns multiple findings, all with conversion errors
		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					Error: fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project1/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project1/uv.lock",
					},
				},
				{
					Error: fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project2/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project2/uv.lock",
					},
				},
			},
		}

		// Legacy workflow should return exit code 3 (no projects found) when all findings have errors
		exitError3 := mockExitError{code: 3}
		legacyMock.ReturnError = exitError3

		depGraphs, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		// Current behavior: when all findings have errors but len(findings) > 0, exit code 3 from legacy workflow
		// returns nil, nil (no error), so we get empty workflowData with no error.
		// This may be a bug - we should check for valid findings, not just len(findings) > 0.
		// For now, test matches current behavior.
		require.NoError(t, err)
		assert.NotNil(t, depGraphs)
		assert.Len(t, depGraphs, 0, "Should return empty workflowData when all findings have errors and legacy workflow returns exit code 3")
		assert.True(t, legacyMock.Called(), "legacy plugin should be called when allProjects is true")
	})

	t.Run("should return only first finding when FlagAllProjects is false", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, false)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		// Should only have one finding even if multiple plugins could return findings
		assert.Len(t, workflowData, 1)
		assert.False(t, legacyMock.Called(), "legacy plugin should not be called")
	})

	t.Run("handleSBOMResolution with FlagAllProjects", func(t *testing.T) {
		finding1 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "pip", "project-1", "1.0.0"),
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					TargetFile: stringPtr("pyproject.toml"),
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				NormalisedTargetFile: "pyproject.toml",
			},
		}
		finding2 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "pip", "project-2", "2.0.0"),
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					TargetFile: stringPtr("subproject/pyproject.toml"),
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				NormalisedTargetFile: "subproject/pyproject.toml",
			},
		}
		finding3 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "npm", "project-3", "3.0.0"),
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					TargetFile: stringPtr("package.json"),
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				NormalisedTargetFile: "package.json",
			},
		}
		finding4 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "gomod", "project-4", "4.0.0"),
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					TargetFile: stringPtr("go.mod"),
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				NormalisedTargetFile: "go.mod",
			},
		}

		tc := []struct {
			name                             string
			allProjects                      bool
			initialExclude                   string
			plugins                          []ecosystems.SCAPlugin
			expectedWorkflowDataLen          int
			expectLegacyResolutionToBeCalled bool
			expectedExclude                  string
			expectedExcludePaths             string
			pluginsShouldNotBeCalled         []int
		}{
			{
				name:           "should return all findings from single plugin when FlagAllProjects is false (e.g. single workspace project with multiple findings)",
				allProjects:    false,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						results: []ecosystems.SCAResult{
							finding1,
							finding2,
						},
					},
				},
				expectedWorkflowDataLen:          2,
				expectLegacyResolutionToBeCalled: false,
				expectedExclude:                  "",
				expectedExcludePaths:             "",
			},
			{
				name:           "should return all findings when FlagAllProjects is true",
				allProjects:    true,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						results: []ecosystems.SCAResult{
							withProcessedFiles(finding1, "uv.lock", "pyproject.toml", "requirements.txt", "setup.py"),
							finding2,
						},
					},
				},
				// Expected: 2 SBOM findings + 1 legacy workflow depgraph = 3
				expectedWorkflowDataLen:          3,
				expectLegacyResolutionToBeCalled: true,
				expectedExclude:                  "",
				expectedExcludePaths:             "uv.lock,pyproject.toml,requirements.txt,setup.py",
			},
			{
				name:           "should continue to next plugin when first plugin returns zero findings and FlagAllProjects is false",
				allProjects:    false,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{},
					&mockScaPlugin{
						results: []ecosystems.SCAResult{finding1},
					},
				},
				expectedWorkflowDataLen:          1,
				expectLegacyResolutionToBeCalled: false,
				expectedExclude:                  "",
				expectedExcludePaths:             "",
			},
			{
				name:           "should stop at first plugin and return its findings when FlagAllProjects is false",
				allProjects:    false,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						results: []ecosystems.SCAResult{finding1, finding2},
					},
					&mockScaPlugin{
						results: []ecosystems.SCAResult{finding3, finding4},
					},
				},
				expectedWorkflowDataLen:          2,
				expectLegacyResolutionToBeCalled: false,
				expectedExclude:                  "",
				expectedExcludePaths:             "",
				pluginsShouldNotBeCalled:         []int{1},
			},
			{
				name:           "should return all findings when FlagAllProjects is true and multiple plugins return multiple findings",
				allProjects:    true,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						results: []ecosystems.SCAResult{
							withProcessedFiles(finding1, "uv.lock", "pyproject.toml", "requirements.txt", "setup.py"),
							finding2,
						},
					},
					&mockScaPlugin{
						results: []ecosystems.SCAResult{
							withProcessedFiles(finding3, "package.json", "go.mod"),
							finding4,
						},
					},
				},
				// Expected: 4 SBOM findings + 1 legacy workflow depgraph = 5
				expectedWorkflowDataLen:          5,
				expectLegacyResolutionToBeCalled: true,
				expectedExclude:                  "",
				expectedExcludePaths:             "uv.lock,pyproject.toml,requirements.txt,setup.py,package.json,go.mod",
			},
			{
				name:           "should call legacy resolution workflow when no SBOM findings are found and FlagAllProjects is false",
				allProjects:    false,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{},
					&mockScaPlugin{},
				},
				expectedWorkflowDataLen:          1,
				expectLegacyResolutionToBeCalled: true,
				expectedExclude:                  "",
				expectedExcludePaths:             "",
			},
			{
				name:           "should put ProcessedFiles in FlagExcludePaths and leave user FlagExclude untouched",
				allProjects:    true,
				initialExclude: "existing-file.txt,another-file.py",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						results: []ecosystems.SCAResult{
							withProcessedFiles(finding1, "uv.lock", "pyproject.toml", "requirements.txt", "setup.py"),
							finding2,
						},
					},
				},
				// Expected: 2 SBOM findings + 1 legacy workflow depgraph = 3
				expectedWorkflowDataLen:          3,
				expectLegacyResolutionToBeCalled: true,
				expectedExclude:                  "existing-file.txt,another-file.py",
				expectedExcludePaths:             "uv.lock,pyproject.toml,requirements.txt,setup.py",
			},
		}

		for _, tc := range tc {
			t.Run(tc.name, func(t *testing.T) {
				mr := make([]mocks.MockResponse, tc.expectedWorkflowDataLen)
				for i := 0; i < tc.expectedWorkflowDataLen; i++ {
					mr[i] = mocks.NewMockResponse("application/json", []byte(uvSBOMConvertResponse), http.StatusOK)
				}
				mockSBOMService := mocks.NewMockSBOMServiceMultiResponse(
					mr,
					func(r *http.Request) {
						assert.Equal(t, http.MethodPost, r.Method)
						assert.Contains(t, r.RequestURI, "/hidden/orgs/test-org-id/sboms/convert")
					},
				)
				defer mockSBOMService.Close()

				ctx := setupTestContext(t, true)
				legacyMock := NewLegacyHarness(ctx)
				ctx.config.Set(workflow.FlagAllProjects, tc.allProjects)
				ctx.config.Set(workflow.FlagExclude, tc.initialExclude)
				ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

				if tc.expectLegacyResolutionToBeCalled {
					legacyMock.ReturnTargets = []string{"legacy-target/package.json"}
				}

				workflowData, err := handleSBOMResolutionDI(
					ctx.invocationContext,
					ctx.config,
					&nopLogger,
					append(tc.plugins, legacyMock.Plugin),
				)

				require.NoError(t, err)
				assert.NotNil(t, workflowData)
				assert.Len(t, workflowData, tc.expectedWorkflowDataLen)
				assert.Equal(t, tc.expectLegacyResolutionToBeCalled, legacyMock.Called())

				if tc.expectLegacyResolutionToBeCalled {
					assert.Equal(t, tc.expectedExclude, legacyMock.CapturedExclude(),
						"legacy plugin should see FlagExclude unchanged from the user-supplied value")
					assert.Equal(t, tc.expectedExcludePaths, legacyMock.CapturedExcludePaths(),
						"legacy plugin should see ProcessedFiles from earlier plugins on FlagExcludePaths")
				}

				for _, idx := range tc.pluginsShouldNotBeCalled {
					plugin, ok := tc.plugins[idx].(*mockScaPlugin)
					require.True(t, ok, "expected plugin at index %d to be *mockScaPlugin", idx)
					assert.Nil(t, plugin.options, "plugin at index %d should not have been called", idx)
				}
			})
		}
	})

	t.Run("should handle exit code 3 (no projects found) gracefully and continue with SBOM data", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		// Create mock plugin that returns a finding
		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				}, "uv.lock"),
			},
		}

		// Create an error with exit code 3 (no projects found)
		exitError3 := mockExitError{code: 3}
		legacyMock.ReturnError = exitError3

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		// Should succeed and return SBOM data despite exit code 3 from legacy workflow
		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		// Should have 1 SBOM finding (legacy workflow returned exit code 3, so no legacy data)
		assert.Len(t, workflowData, 1)
		// Legacy resolution should have been called
		assert.True(t, legacyMock.Called(), "legacy plugin should be called")
		assert.Equal(t, "uv.lock", legacyMock.CapturedExcludePaths(),
			"legacy plugin should see ProcessedFiles on FlagExcludePaths at invocation")
	})

	t.Run("should handle exit code 3 when no SBOM findings are found", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, false)

		// Create mock plugin that returns no findings
		mockPlugin := &mockScaPlugin{}

		// Create an error with exit code 3 (no projects found)
		exitError3 := mockExitError{code: 3}
		legacyMock.ReturnError = exitError3

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		// Should return error when exit code 3 occurs with no SBOM findings
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no supported projects detected")
		var ec legacycli.ExitCoder
		require.True(t, errors.As(err, &ec), "no supported projects error should carry an exit code")
		assert.Equal(t, 3, ec.ExitCode())
		assert.Nil(t, workflowData)
		// Legacy resolution should have been called
		assert.True(t, legacyMock.Called(), "legacy plugin should be called")
	})

	t.Run("should return error for non-exit-code-3 errors from legacy workflow", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		// Create mock plugin that returns a finding
		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				}, "uv.lock"),
			},
		}

		// Create an error with exit code 1 (not exit code 3)
		exitError1 := mockExitError{code: 1}
		legacyMock.ReturnError = exitError1

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		// Should return error for non-exit-code-3 errors
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error handling legacy workflow")
		assert.Nil(t, workflowData)
		// Legacy resolution should have been called
		assert.True(t, legacyMock.Called(), "legacy plugin should be called")
		assert.Equal(t, "uv.lock", legacyMock.CapturedExcludePaths(),
			"legacy plugin should see ProcessedFiles on FlagExcludePaths at invocation")
	})

	t.Run("should skip findings with errors when legacy workflow returns no data", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		ctx.config.Set(workflow.FlagAllProjects, true)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		legacyMock := NewLegacyHarness(ctx)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project1/pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project1/pyproject.toml",
					},
					Error: nil,
				}, "project1/uv.lock", "project2/uv.lock"),
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project2/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project2/uv.lock",
					},
					Error: fmt.Errorf("failed to generate SBOM"),
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 1, "Should return only the valid finding since legacy workflow returns nil")
		assert.True(t, legacyMock.Called(), "legacy plugin should be called")
		assert.Equal(t, "project1/uv.lock,project2/uv.lock", legacyMock.CapturedExcludePaths(),
			"legacy plugin should see ProcessedFiles on FlagExcludePaths at invocation")
	})

	t.Run("should log snyk_errors.Error details for support debugging", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		ctx.config.Set(workflow.FlagAllProjects, true) // allProjects must be true for errors to be skipped and logged

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information for support debugging",
		}

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "uv.lock",
					},
					Error: snykErr,
				}, "uv.lock"),
			},
		}

		var logBuffer bytes.Buffer
		testLogger := zerolog.New(&logBuffer)

		legacyMock := NewLegacyHarness(ctx)

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&testLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 0, "Should skip finding with error")

		// Verify that the log output contains the detail
		logOutput := logBuffer.String()
		assert.Contains(t, logOutput, "Detailed error information for support debugging",
			"Log should contain snyk_errors.Error Detail field for support debugging")
		assert.Contains(t, logOutput, "Skipping result for",
			"Log should contain the error context")
	})

	t.Run("should pass strict-out-of-sync=false to plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagStrictOutOfSync, "false")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.True(t, mockPlugin.options.Global.AllowOutOfSync)
	})

	t.Run("should default to strict-out-of-sync=true in plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.False(t, mockPlugin.options.Global.AllowOutOfSync)
	})

	t.Run("should ignore invalid strict-out-of-sync values and default to true", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagStrictOutOfSync, "invalid")

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		require.NotNil(t, mockPlugin.options, "plugin should be called when strict-out-of-sync is invalid")
		assert.False(t, mockPlugin.options.Global.AllowOutOfSync, "invalid strict-out-of-sync should default to strict mode")
		assert.False(t, legacyMock.Called(), "legacy plugin should not be called when a plugin finding is returned")
	})

	t.Run("should pass exclude flag to plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)
		ctx.config.Set(workflow.FlagExclude, "dir1, dir2 ,dir3")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		defer mockSBOMService.Close()
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.Equal(t, []string{"dir1", "dir2", "dir3"}, []string(mockPlugin.options.Global.Exclude))
		assert.True(t, mockPlugin.options.Global.AllProjects)
	})

	t.Run("should pass file flag to plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagFile, "Gemfile")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		defer mockSBOMService.Close()
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		require.NotNil(t, mockPlugin.options.Global.TargetFile)
		assert.Equal(t, "Gemfile", *mockPlugin.options.Global.TargetFile)
	})

	t.Run("should handle empty exclude flag", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagExclude, "")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		defer mockSBOMService.Close()
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.Nil(t, mockPlugin.options.Global.Exclude)
	})

	t.Run("should handle legacy workflow data with errors attached and output warnings", func(t *testing.T) {
		ctx := setupTestContext(t, false)
		ctx.config.Set(workflow.FlagAllProjects, true)

		// Create mock plugin that returns no findings to trigger legacy workflow
		mockPlugin := &mockScaPlugin{}

		// One valid line plus one error-bearing line; the latter is what should produce
		// the warning output the test asserts on below.
		legacyMock := NewLegacyHarness(ctx)
		legacyMock.ReturnLines = []string{
			MakeLegacyJSONLLine("legacy-project/valid.json"),
			MakeLegacyJSONLLineWithErrorCatalog(
				"legacy-project/requirements.txt",
				"SNYK-LEGACY-001",
				"Legacy Error Title",
				"Detailed legacy error information for debugging",
			),
		}

		// Capture the output to verify it contains expected error messages
		var capturedOutput string
		ctx.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...ui.Opts) error {
			capturedOutput = err.Error()
			return nil
		}).Times(1)

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 1, "Should return only the valid data, filtering out error data")
		assert.True(t, legacyMock.Called(), "legacy plugin should be called")

		// Verify that the warning output contains the legacy error details
		assert.Contains(t, capturedOutput, "legacy-project/requirements.txt", "Output should mention the problem file")
		assert.Contains(t, capturedOutput, "Detailed legacy error information for debugging",
			"Output should include snyk_errors.Error Detail field from legacy data")
		assert.Contains(t, capturedOutput, "1/2 potential projects failed to get dependencies",
			"Output should include number of failed potential projects")
	})

	t.Run("should return snyk_errors.Error when finding has error and allProjects is false", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, false)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information for support debugging",
		}

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "uv.lock",
					},
					Error: snykErr,
				}, "uv.lock"),
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)
		assert.False(t, legacyMock.Called(), "legacy plugin should not be called when error is returned early")

		// Verify the returned error is a snyk_errors.Error
		var returnedSnykErr snyk_errors.Error
		require.True(t, errors.As(err, &returnedSnykErr), "returned error should be a snyk_errors.Error")
		assert.Equal(t, "SNYK-TEST-001", returnedSnykErr.ID)
		assert.Equal(t, "Test Error Title", returnedSnykErr.Title)
		assert.Equal(t, "Detailed error information for support debugging", returnedSnykErr.Detail)
	})

	t.Run("should fail fast and return exit code 2 when fail-fast is enabled with all-projects", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)
		ctx.config.Set(workflow.FlagFailFast, true)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information for debugging",
		}

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("valid-project/pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "valid-project/pyproject.toml",
					},
					Error: nil,
				}, "project1/uv.lock", "project2/uv.lock"),
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project1/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project1/uv.lock",
					},
					Error: snykErr,
				},
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project2/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project2/uv.lock",
					},
					Error: fmt.Errorf("This should not be processed"),
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)
		assert.False(t, legacyMock.Called(), "legacy plugin should not be called when fail-fast triggers")

		var ec legacycli.ExitCoder
		require.True(t, errors.As(err, &ec), "error should implement ExitCoder")
		assert.Equal(t, 2, ec.ExitCode(), "exit code should be 2 for fail-fast")
		assert.Contains(t, err.Error(), "project1/uv.lock")
	})

	t.Run("should fail fast on first error with snyk error details", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)
		ctx.config.Set(workflow.FlagFailFast, true)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-002",
			Title:  "SBOM Conversion Failed",
			Detail: "The SBOM document could not be converted due to invalid format",
		}

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project1/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project1/uv.lock",
					},
					Error: snykErr,
				}, "project1/uv.lock"),
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)
		assert.Contains(t, err.Error(), "The SBOM document could not be converted due to invalid format")
		assert.Contains(t, err.Error(), "project1/uv.lock")

		var ec legacycli.ExitCoder
		require.True(t, errors.As(err, &ec), "error should implement ExitCoder")
		assert.Equal(t, 2, ec.ExitCode())
	})

	t.Run("should not fail fast when fail-fast is false with all-projects", func(t *testing.T) {
		ctx := setupTestContext(t, false)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)
		ctx.config.Set(workflow.FlagFailFast, false)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error to help the customer debug the issue",
		}

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("valid-project/pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "valid-project/pyproject.toml",
					},
					Error: nil,
				}, "project1/uv.lock"),
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project1/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project1/uv.lock",
					},
					Error: snykErr,
				},
			},
		}

		legacyMock.ReturnTargets = []string{"legacy-target/package.json"}

		var capturedOutput string
		ctx.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...ui.Opts) error {
			capturedOutput = err.Error()
			return nil
		}).Times(1)

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.True(t, legacyMock.Called(), "legacy plugin should be called")
		assert.Equal(t, "project1/uv.lock", legacyMock.CapturedExcludePaths(),
			"legacy plugin should see ProcessedFiles on FlagExcludePaths at invocation")
		assert.Contains(t, capturedOutput, "project1/uv.lock")
	})

	t.Run("should ignore fail-fast when all-projects is false", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, false)
		ctx.config.Set(workflow.FlagFailFast, true)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information",
		}

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "uv.lock",
					},
					Error: snykErr,
				}, "uv.lock"),
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)

		var ec legacycli.ExitCoder
		if errors.As(err, &ec) {
			assert.NotEqual(t, 2, ec.ExitCode(), "exit code should not be 2 when all-projects is false")
		}
	})

	t.Run("should pass fail-fast flag to plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)
		ctx.config.Set(workflow.FlagFailFast, true)

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "pyproject.toml",
					},
				},
			},
		}

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.True(t, mockPlugin.options.Global.FailFast, "FailFast should be true in plugin options")
	})

	t.Run("should output problem findings through UI when allProjects is true", func(t *testing.T) {
		ctx := setupTestContext(t, false)
		legacyMock := NewLegacyHarness(ctx)
		ctx.config.Set(workflow.FlagAllProjects, true)

		// Create a snyk error and a regular error
		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error to help the customer debug the issue",
		}
		regularErr := fmt.Errorf("Failure message should not be shown to the user")

		mockPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				withProcessedFiles(ecosystems.SCAResult{
					DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("valid-project/pyproject.toml"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "valid-project/pyproject.toml",
					},
					Error: nil,
				}, "project1/uv.lock", "project2/uv.lock"),
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project1/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project1/uv.lock",
					},
					Error: snykErr,
				},
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{
							TargetFile: stringPtr("project2/uv.lock"),
						},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "project2/uv.lock",
					},
					Error: regularErr,
				},
			},
		}

		legacyMock.ReturnTargets = []string{"legacy-target/package.json"}

		// Capture the output to verify it contains expected error messages
		var capturedOutput string
		ctx.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...ui.Opts) error {
			capturedOutput = err.Error()
			return nil
		}).Times(1)

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)

		assert.Equal(t, "project1/uv.lock,project2/uv.lock", legacyMock.CapturedExcludePaths(),
			"legacy plugin should see ProcessedFiles on FlagExcludePaths at invocation")
		assert.Contains(t, capturedOutput, "project1/uv.lock", "Output should mention the first problem file")
		assert.Contains(t, capturedOutput, "project2/uv.lock", "Output should mention the second problem file")
		assert.Contains(t, capturedOutput, "Detailed error to help the customer debug the issue",
			"Output should include snyk_errors.Error Detail field")
		assert.Contains(t, capturedOutput, "could not process manifest file",
			"Output should output a generic message rather than the error details of a non-snyk error")
		assert.Contains(t, capturedOutput, "2/4 potential projects failed to get dependencies",
			"Output should include number of failed potential projects")
	})
}

func Test_parseExcludeFlag(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string returns nil",
			input:    "",
			expected: nil,
		},
		{
			name:     "single value",
			input:    "dir1",
			expected: []string{"dir1"},
		},
		{
			name:     "multiple values",
			input:    "dir1,dir2,dir3",
			expected: []string{"dir1", "dir2", "dir3"},
		},
		{
			name:     "trims whitespace around values",
			input:    "dir1, dir2 , dir3",
			expected: []string{"dir1", "dir2", "dir3"},
		},
		{
			name:     "filters empty entries",
			input:    "dir1,,dir2,",
			expected: []string{"dir1", "dir2"},
		},
		{
			name:     "only commas returns nil",
			input:    ",,,",
			expected: nil,
		},
		{
			name:     "whitespace only entries are filtered",
			input:    "dir1,   ,dir2",
			expected: []string{"dir1", "dir2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseExcludeFlag(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test_processedFilesFlowFromPluginsToExcludeConfig locks in the end-to-end contract that
// the legacy CLI subprocess sees the full union of paths to skip: the user's --exclude-paths
// flag combined with every earlier plugin's ProcessedFiles. The union is built up on
// pluginOptions.Global.ExcludePaths during the plugin loop, and the legacy plugin (the last
// plugin in the chain) translates it into the legacy CLI's --exclude-paths flag.
func Test_processedFilesFlowFromPluginsToExcludeConfig(t *testing.T) {
	pluginWithProcessedFiles := func(targetFile, name string, processedFiles []string) *mockScaPlugin {
		return &mockScaPlugin{
			results: []ecosystems.SCAResult{{
				DepGraph: createTestDepGraph(t, "pip", name, "1.0.0"),
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{TargetFile: stringPtr(targetFile)},
				},
				ResolverMetadata: &ecosystems.ResolverMetadata{
					NormalisedTargetFile: targetFile,
				},
				ProcessedFiles: processedFiles,
			}},
		}
	}

	testCases := []struct {
		name                 string
		userExcludePaths     string
		plugins              func() []ecosystems.SCAPlugin
		expectedExcludePaths string
	}{
		{
			name: "union of every plugin's ProcessedFiles",
			plugins: func() []ecosystems.SCAPlugin {
				return []ecosystems.SCAPlugin{
					pluginWithProcessedFiles("pyproject.toml", "project-1", []string{"file1.py", "file2.py"}),
					pluginWithProcessedFiles("package.json", "project-2", []string{"file3.py"}),
				}
			},
			expectedExcludePaths: "file1.py,file2.py,file3.py",
		},
		{
			name:             "user --exclude-paths value is preserved alongside processed files",
			userExcludePaths: "user-supplied.txt",
			plugins: func() []ecosystems.SCAPlugin {
				return []ecosystems.SCAPlugin{
					pluginWithProcessedFiles("pyproject.toml", "project-1", []string{"file1.py"}),
				}
			},
			expectedExcludePaths: "user-supplied.txt,file1.py",
		},
		{
			name:             "user --exclude-paths value alone when no plugin produced ProcessedFiles",
			userExcludePaths: "user-supplied.txt",
			plugins: func() []ecosystems.SCAPlugin {
				return []ecosystems.SCAPlugin{&mockScaPlugin{results: nil}}
			},
			expectedExcludePaths: "user-supplied.txt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := setupTestContext(t, true)
			ctx.config.Set(workflow.FlagAllProjects, true)
			if tc.userExcludePaths != "" {
				ctx.config.Set(workflow.FlagExcludePaths, tc.userExcludePaths)
			}

			legacyMock := NewLegacyHarness(ctx)
			legacyMock.ReturnTargets = []string{"legacy-target/package.json"}

			plugins := append(tc.plugins(), legacyMock.Plugin)

			_, err := handleSBOMResolutionDI(
				ctx.invocationContext,
				ctx.config,
				&nopLogger,
				plugins,
			)

			require.NoError(t, err)
			require.True(t, legacyMock.Called())
			assert.Equal(t, tc.expectedExcludePaths, legacyMock.CapturedExcludePaths())
		})
	}
}

func Test_uvWorkspacePackages_passesOptionToPlugin(t *testing.T) {
	ctx := setupTestContext(t, true)
	legacyMock := NewLegacyHarness(ctx)
	ctx.config.Set(workflow.FlagUvWorkspacePackages, true)
	ctx.config.Set(workflow.FlagFile, "uv.lock")

	mockPlugin := &mockScaPlugin{
		results: []ecosystems.SCAResult{
			{
				DepGraph: createTestDepGraph(t, "uv", "pkg-a", "1.0.0"),
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						TargetFile: stringPtr("pyproject.toml"),
					},
				},
				ResolverMetadata: &ecosystems.ResolverMetadata{
					NormalisedTargetFile: "pyproject.toml",
				},
			},
		},
	}

	_, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
	)

	require.NoError(t, err)
	require.NotNil(t, mockPlugin.options)
	assert.True(t, mockPlugin.options.Global.ForceIncludeWorkspacePackages, "ForceIncludeWorkspacePackages should be passed to the plugin")
	assert.False(t, mockPlugin.options.Global.AllProjects, "AllProjects should remain false")
	assert.False(t, legacyMock.Called(), "legacy workflow should not be called when UvWorkspacePackages is set")
	require.NotNil(t, mockPlugin.options.Global.TargetFile)
	assert.Equal(t, "uv.lock", *mockPlugin.options.Global.TargetFile)
}

func Test_uvWorkspacePackages_combinesMultipleDepGraphsAsJSONL(t *testing.T) {
	ctx := setupTestContext(t, true)
	legacyMock := NewLegacyHarness(ctx)
	ctx.config.Set(workflow.FlagFile, "uv.lock")
	ctx.config.Set(workflow.FlagUvWorkspacePackages, true)

	mockPlugin := &mockScaPlugin{
		name: uv.PluginName,
		results: []ecosystems.SCAResult{
			{
				DepGraph: createTestDepGraph(t, "uv", "pkg-a", "1.0.0"),
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						TargetFile: stringPtr("pyproject.toml"),
					},
				},
				ResolverMetadata: &ecosystems.ResolverMetadata{
					NormalisedTargetFile: "pyproject.toml",
				},
			},
			{
				DepGraph: createTestDepGraph(t, "uv", "pkg-b", "2.0.0"),
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						TargetFile: stringPtr("packages/pkg-b/pyproject.toml"),
					},
				},
				ResolverMetadata: &ecosystems.ResolverMetadata{
					NormalisedTargetFile: "packages/pkg-b/pyproject.toml",
				},
			},
		},
	}

	workflowDataResult, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
	)

	require.NoError(t, err)
	require.Len(t, workflowDataResult, 1, "multiple findings should be combined into a single workflow.Data")
	assert.False(t, legacyMock.Called(), "legacy workflow should not be called")

	workflowData := workflowDataResult[0]
	payload, ok := workflowData.GetPayload().([]byte)
	require.True(t, ok)

	type jsonlLine struct {
		DepGraph   json.RawMessage `json:"depGraph"`
		TargetFile string          `json:"targetFile"`
	}

	lines := bytes.Split(payload, []byte("\n"))
	require.Len(t, lines, 2, "JSONL should contain two lines")

	var line1, line2 jsonlLine
	require.NoError(t, json.Unmarshal(lines[0], &line1), "line 1 should be valid JSON")
	require.NoError(t, json.Unmarshal(lines[1], &line2), "line 2 should be valid JSON")

	assert.Equal(t, "pyproject.toml", line1.TargetFile)
	assert.NotEmpty(t, line1.DepGraph, "line 1 should have a depGraph")

	assert.Equal(t, "packages/pkg-b/pyproject.toml", line2.TargetFile)
	assert.NotEmpty(t, line2.DepGraph, "line 2 should have a depGraph")

	// check metadata is set correctly
	contentLocation, err := workflowData.GetMetaData(workflow.ContentLocationKey)
	require.NoError(t, err)
	assert.Equal(t, "pyproject.toml", contentLocation, "Content-Location should be set to the first result's TargetFile")

	normalisedTargetFile, err := workflowData.GetMetaData(workflow.MetaKeyNormalisedTargetFile)
	require.NoError(t, err)
	assert.Equal(t, "pyproject.toml", normalisedTargetFile, "normalisedTargetFile should be set to the first result's TargetFile")

	targetFileFromPlugin, err := workflowData.GetMetaData(workflow.MetaKeyTargetFileFromPlugin)
	require.NoError(t, err)
	assert.Equal(t, "pyproject.toml", targetFileFromPlugin,
		"MetaKeyTargetFileFromPlugin is emitted from Identity.TargetFile whenever the plugin sets it (uv does)")
}

func Test_uvWorkspacePackages_returnsErrorWhenFindingHasError(t *testing.T) {
	ctx := setupTestContext(t, true)
	legacyMock := NewLegacyHarness(ctx)
	ctx.config.Set(workflow.FlagUvWorkspacePackages, true)
	ctx.config.Set(workflow.FlagFile, "uv.lock")

	snykErr := snyk_errors.Error{
		ID:     "SNYK-TEST-001",
		Title:  "Test Error Title",
		Detail: "Detailed error information for support debugging",
	}

	mockPlugin := &mockScaPlugin{
		name: uv.PluginName,
		results: []ecosystems.SCAResult{
			{
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						TargetFile: stringPtr("uv.lock"),
					},
				},
				ResolverMetadata: &ecosystems.ResolverMetadata{
					NormalisedTargetFile: "uv.lock",
				},
				Error: snykErr,
			},
		},
	}

	workflowData, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
	)

	require.Error(t, err)
	assert.Nil(t, workflowData)
	assert.False(t, legacyMock.Called(), "legacy workflow should not be called when error is returned early")

	var returnedSnykErr snyk_errors.Error
	require.True(t, errors.As(err, &returnedSnykErr), "returned error should be a snyk_errors.Error")
	assert.Equal(t, "SNYK-TEST-001", returnedSnykErr.ID)
	assert.Equal(t, "Test Error Title", returnedSnykErr.Title)
	assert.Equal(t, "Detailed error information for support debugging", returnedSnykErr.Detail)
}

func Test_uvWorkspacePackages_legacyResultsAppendedIndividually(t *testing.T) {
	ctx := setupTestContext(t, true)
	ctx.config.Set(workflow.FlagFile, "uv.lock")
	ctx.config.Set(workflow.FlagUvWorkspacePackages, true)
	ctx.config.Set(workflow.FlagAllProjects, true)

	mockPlugin := &mockScaPlugin{
		name: uv.PluginName,
		results: []ecosystems.SCAResult{
			{
				DepGraph: createTestDepGraph(t, "uv", "pkg-a", "1.0.0"),
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						TargetFile: stringPtr("pyproject.toml"),
					},
				},
				ResolverMetadata: &ecosystems.ResolverMetadata{
					NormalisedTargetFile: "pyproject.toml",
				},
			},
			{
				DepGraph: createTestDepGraph(t, "uv", "pkg-b", "2.0.0"),
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{
						TargetFile: stringPtr("packages/pkg-b/pyproject.toml"),
					},
				},
				ResolverMetadata: &ecosystems.ResolverMetadata{
					NormalisedTargetFile: "packages/pkg-b/pyproject.toml",
				},
			},
		},
	}

	legacyMock := NewLegacyHarness(ctx)
	legacyMock.ReturnTargets = []string{"legacy/one.gradle", "legacy/two.gradle"}

	workflowData, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin, legacyMock.Plugin},
	)

	require.NoError(t, err)
	require.True(t, legacyMock.Called(), "legacy resolution should run when allProjects=true")
	require.Len(t, workflowData, 3, "expected 1 JSONL bundle from plugin + 2 individual workflow.Data from legacy")

	bundlePayload, ok := workflowData[0].GetPayload().([]byte)
	require.True(t, ok, "first workflow.Data should carry the JSONL bundle payload")
	bundleLines := bytes.Split(bundlePayload, []byte("\n"))
	require.Len(t, bundleLines, 2, "plugin results should be bundled into 2 JSONL lines")

	type jsonlLine struct {
		DepGraph   json.RawMessage `json:"depGraph"`
		TargetFile string          `json:"targetFile"`
	}
	var line1, line2 jsonlLine
	require.NoError(t, json.Unmarshal(bundleLines[0], &line1))
	require.NoError(t, json.Unmarshal(bundleLines[1], &line2))
	assert.Equal(t, "pyproject.toml", line1.TargetFile)
	assert.Equal(t, "packages/pkg-b/pyproject.toml", line2.TargetFile)

	secondLoc, err := workflowData[1].GetMetaData(workflow.ContentLocationKey)
	require.NoError(t, err)
	assert.Equal(t, "legacy/one.gradle", secondLoc, "legacy results should be appended individually, with their own target")

	thirdLoc, err := workflowData[2].GetMetaData(workflow.ContentLocationKey)
	require.NoError(t, err)
	assert.Equal(t, "legacy/two.gradle", thirdLoc, "legacy results should be appended individually, with their own target")
}

// Test_handleSBOMResolutionDI_perResultErrorMatrix locks in the failure semantics for per-result
// errors across (allProjects, failFast) combinations. The behavior is uniform across plugins:
// the orchestrator does not special-case any plugin's results for error handling.
//
//   - !allProjects             → halt (the user asked for one project; that one errored).
//   - allProjects + !failFast  → continue, render as warnings, return successful results.
//   - allProjects + failFast   → halt with exit code 2.
func Test_handleSBOMResolutionDI_perResultErrorMatrix(t *testing.T) {
	pluginErroredResult := func() *mockScaPlugin {
		return &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "pip", "good", "1.0.0"),
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{TargetFile: stringPtr("good/requirements.txt")},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "good/requirements.txt",
					},
				},
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{TargetFile: stringPtr("broken/requirements.txt")},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "broken/requirements.txt",
					},
					Error: snyk_errors.Error{Title: "Resolution failed", Detail: "missing dep"},
				},
			},
		}
	}

	t.Run("!allProjects: per-result error halts the scan", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		ctx.config.Set(workflow.FlagAllProjects, false)

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{pluginErroredResult()},
		)

		require.Error(t, err, "an errored result must fail the scan in !allProjects mode")
	})

	t.Run("allProjects + !failFast: errors become warnings, successful results returned", func(t *testing.T) {
		ctx := setupTestContext(t, false)
		ctx.config.Set(workflow.FlagAllProjects, true)
		ctx.userInterface.EXPECT().OutputError(gomock.Any()).Return(nil).Times(1)

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{pluginErroredResult()},
		)

		require.NoError(t, err, "errored results should not halt under allProjects without fail-fast")
		assert.Len(t, workflowData, 1, "the successful result is returned alongside the warning")
	})

	t.Run("allProjects + failFast: per-result error halts with exit code 2", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		ctx.config.Set(workflow.FlagAllProjects, true)
		ctx.config.Set(workflow.FlagFailFast, true)

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{pluginErroredResult()},
		)

		require.Error(t, err)
		var ec legacycli.ExitCoder
		require.True(t, errors.As(err, &ec), "fail-fast must surface an exit-coded error")
		assert.Equal(t, 2, ec.ExitCode())
	})
}

func Test_handleSBOMResolutionDI_noSupportedProjectsDetectedWhenAllPluginsReturnZero(t *testing.T) {
	t.Run("two plugins both empty", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		emptyPlugin1 := &mockScaPlugin{results: nil}
		emptyPlugin2 := &mockScaPlugin{results: nil}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{emptyPlugin1, emptyPlugin2},
		)

		require.Error(t, err)
		assert.EqualError(t, err, "no supported projects detected")
		var ec legacycli.ExitCoder
		require.True(t, errors.As(err, &ec), "no supported projects error should carry an exit code")
		assert.Equal(t, 3, ec.ExitCode())
		assert.Nil(t, workflowData)
	})

	t.Run("single empty plugin", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		emptyPlugin := &mockScaPlugin{results: nil}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{emptyPlugin},
		)

		require.Error(t, err)
		assert.EqualError(t, err, "no supported projects detected")
		var ec legacycli.ExitCoder
		require.True(t, errors.As(err, &ec), "no supported projects error should carry an exit code")
		assert.Equal(t, 3, ec.ExitCode())
		assert.Nil(t, workflowData)
	})

	t.Run("does not fire when at least one plugin returns a result, even if errored", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		ctx.config.Set(workflow.FlagAllProjects, true)
		erroredPlugin := &mockScaPlugin{
			results: []ecosystems.SCAResult{
				{
					ProjectDescriptor: identity.ProjectDescriptor{
						Identity: identity.ProjectIdentity{TargetFile: stringPtr("broken/pom.xml")},
					},
					ResolverMetadata: &ecosystems.ResolverMetadata{
						NormalisedTargetFile: "broken/pom.xml",
					},
					Error: fmt.Errorf("module failed to resolve"),
				},
			},
		}
		emptyPlugin := &mockScaPlugin{results: nil}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{erroredPlugin, emptyPlugin},
		)

		require.NoError(t, err, "totalResults > 0 because the errored result still counts as a result")
		assert.NotNil(t, workflowData)
		assert.Empty(t, workflowData, "errored result becomes a warning, no workflow data is produced")
	})
}

// TestWorkflowDataFromDepGraph documents the workflow.Data metadata emission contract.
// ContentLocationKey and MetaKeyNormalisedTargetFile are always emitted from
// ResolverMetadata.NormalisedTargetFile. MetaKeyTargetFileFromPlugin is emitted only when
// Identity.TargetFile is non-nil (i.e. the per-language plugin set its own targetFile name).
// Downstream consumers treat the absence of MetaKeyTargetFileFromPlugin as a signal, so
// emitting it spuriously must be avoided.
func TestWorkflowDataFromDepGraph(t *testing.T) {
	t.Run("Identity.TargetFile nil → MetaKeyTargetFileFromPlugin suppressed", func(t *testing.T) {
		result := &ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "uv", "test-project", "1.0.0"),
			ResolverMetadata: &ecosystems.ResolverMetadata{
				NormalisedTargetFile: "pyproject.toml",
			},
		}

		data, err := workflowDataFromDepGraph(result)
		require.NoError(t, err)

		contentLocation, err := data.GetMetaData(workflow.ContentLocationKey)
		require.NoError(t, err)
		assert.Equal(t, "pyproject.toml", contentLocation)

		normalised, err := data.GetMetaData(workflow.MetaKeyNormalisedTargetFile)
		require.NoError(t, err)
		assert.Equal(t, "pyproject.toml", normalised)

		_, err = data.GetMetaData(workflow.MetaKeyTargetFileFromPlugin)
		assert.Error(t, err)
	})

	t.Run("Identity.TargetFile set → MetaKeyTargetFileFromPlugin emitted verbatim", func(t *testing.T) {
		result := &ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
			ProjectDescriptor: identity.ProjectDescriptor{
				Identity: identity.ProjectIdentity{
					TargetFile: stringPtr("Pipfile"),
				},
			},
			ResolverMetadata: &ecosystems.ResolverMetadata{
				NormalisedTargetFile: "Pipfile",
			},
		}

		data, err := workflowDataFromDepGraph(result)
		require.NoError(t, err)

		contentLocation, err := data.GetMetaData(workflow.ContentLocationKey)
		require.NoError(t, err)
		assert.Equal(t, "Pipfile", contentLocation)

		normalised, err := data.GetMetaData(workflow.MetaKeyNormalisedTargetFile)
		require.NoError(t, err)
		assert.Equal(t, "Pipfile", normalised)

		fromPlugin, err := data.GetMetaData(workflow.MetaKeyTargetFileFromPlugin)
		require.NoError(t, err)
		assert.Equal(t, "Pipfile", fromPlugin)
	})
}

// stringPtr returns a pointer to the given string value.
func stringPtr(s string) *string {
	return &s
}
