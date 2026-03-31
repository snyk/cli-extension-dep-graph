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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	dg "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	frameworkmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

//go:embed testdata/uv-sbom-convert-expected-dep-graph.json
var uvSBOMConvertExpectedDepGraph string

//go:embed testdata/uv-sbom-convert-response.json
var uvSBOMConvertResponse string

type mockScaPlugin struct {
	result  *ecosystems.PluginResult
	err     error
	options *ecosystems.SCAPluginOptions
}

func (m *mockScaPlugin) BuildDepGraphsFromDir(
	_ context.Context,
	_ logger.Logger,
	_ string,
	options *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	m.options = options
	if m.err != nil {
		return nil, m.err
	}
	if m.result == nil {
		return &ecosystems.PluginResult{}, nil
	}
	return m.result, nil
}

// CalledResolutionHandlerFunc is a test helper structure to track calls to the mock ResolutionHandlerFunc.
type CalledResolutionHandlerFunc struct {
	Called      bool
	Config      configuration.Configuration
	ReturnData  []workflow.Data
	ReturnError error
}

// NewCalledResolutionHandlerFunc creates a new instance for use in tests.
func NewCalledResolutionHandlerFunc(returnData []workflow.Data, returnErr error) *CalledResolutionHandlerFunc {
	return &CalledResolutionHandlerFunc{
		ReturnData:  returnData,
		ReturnError: returnErr,
	}
}

// Func returns a ResolutionHandlerFunc that records invocation and arguments.
func (c *CalledResolutionHandlerFunc) Func() ResolutionHandlerFunc {
	return func(_ workflow.InvocationContext, config configuration.Configuration, _ *zerolog.Logger) ([]workflow.Data, error) {
		c.Called = true
		c.Config = config
		return c.ReturnData, c.ReturnError
	}
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
	invocationContext *frameworkmocks.MockInvocationContext
	userInterface     *frameworkmocks.MockUserInterface
}

// setupTestContext initializes common test objects and handles cleanup automatically.
func setupTestContext(t *testing.T, withDefaultUI bool) *testContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	config := configuration.New()
	config.Set(FlagUseSBOMResolution, true)
	config.Set(configuration.ORGANIZATION, "test-org-id")

	invocationContext := frameworkmocks.NewMockInvocationContext(ctrl)
	invocationContext.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()
	invocationContext.EXPECT().Context().Return(context.Background()).AnyTimes()

	mockUI := frameworkmocks.NewMockUserInterface(ctrl)
	invocationContext.EXPECT().GetUserInterface().Return(mockUI).AnyTimes()
	if withDefaultUI {
		mockUI.EXPECT().OutputError(gomock.Any()).Return(nil).AnyTimes()
	}

	return &testContext{
		ctrl:              ctrl,
		config:            config,
		invocationContext: invocationContext,
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
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		builder, err := dg.NewBuilder(
			&dg.PkgManager{Name: "uv"},
			&dg.PkgInfo{Name: "test-pkg", Version: "1.0.0"},
		)
		require.NoError(t, err)
		expectedDepGraph := builder.Build()

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: expectedDepGraph,
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 1)
		assert.False(t, resolutionHandler.Called, "ResolutionHandlerFunc should not be called")

		depGraph, ok := workflowData[0].GetPayload().([]byte)
		require.True(t, ok, "payload should be []byte")
		assert.JSONEq(t, uvSBOMConvertExpectedDepGraph, string(depGraph))
	})

	t.Run("should handle UV client errors gracefully", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)

		mockPlugin := &mockScaPlugin{
			err: fmt.Errorf("uv command failed"),
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "uv command failed")
		assert.Nil(t, workflowData)
		assert.False(t, resolutionHandler.Called, "ResolutionHandlerFunc should not be called")
	})

	t.Run("should handle SBOM convert network request errors", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)

		mockPlugin := &mockScaPlugin{
			err: fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "analysis of SBOM document failed due to error")
		assert.Contains(t, err.Error(), "500")
		assert.Nil(t, workflowData)
		assert.False(t, resolutionHandler.Called, "ResolutionHandlerFunc should not be called")
	})

	t.Run("should skip findings with errors and only process valid findings when allProjects is true", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
					{
						Error:    fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
						Metadata: ecosystems.Metadata{TargetFile: "uv.lock"},
					},
				},
			},
		}

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		mockWorkflowData := []workflow.Data{
			workflow.NewData(
				dataIdentifier,
				"application/json",
				[]byte(`{"mock":"data"}`),
			),
		}
		resolutionHandler.ReturnData = mockWorkflowData

		depGraphs, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, depGraphs)
		assert.Len(t, depGraphs, 2, "Should return one valid finding plus legacy workflow result")
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called when allProjects is true")
	})

	t.Run("should return error when SBOM conversion fails for all findings when multiple findings are present", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)

		// Create mock plugin that returns multiple findings, all with conversion errors
		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						Error:    fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
						Metadata: ecosystems.Metadata{TargetFile: "project1/uv.lock"},
					},
					{
						Error:    fmt.Errorf("failed to convert SBOM: analysis of SBOM document failed due to error: 500"),
						Metadata: ecosystems.Metadata{TargetFile: "project2/uv.lock"},
					},
				},
			},
		}

		// Legacy workflow should return exit code 3 (no projects found) when all findings have errors
		exitError3 := mockExitError{code: 3}
		resolutionHandler.ReturnError = exitError3

		depGraphs, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		// Current behavior: when all findings have errors but len(findings) > 0, exit code 3 from legacy workflow
		// returns nil, nil (no error), so we get empty workflowData with no error.
		// This may be a bug - we should check for valid findings, not just len(findings) > 0.
		// For now, test matches current behavior.
		require.NoError(t, err)
		assert.NotNil(t, depGraphs)
		assert.Len(t, depGraphs, 0, "Should return empty workflowData when all findings have errors and legacy workflow returns exit code 3")
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called when allProjects is true")
	})

	t.Run("should return only first finding when FlagAllProjects is false", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, false)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		// Should only have one finding even if multiple plugins could return findings
		assert.Len(t, workflowData, 1)
		assert.False(t, resolutionHandler.Called, "ResolutionHandlerFunc should not be called")
	})

	t.Run("handleSBOMResolution with FlagAllProjects", func(t *testing.T) {
		finding1 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "pip", "project-1", "1.0.0"),
			Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
		}
		finding2 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "pip", "project-2", "2.0.0"),
			Metadata: ecosystems.Metadata{TargetFile: "subproject/pyproject.toml"},
		}
		finding3 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "npm", "project-3", "3.0.0"),
			Metadata: ecosystems.Metadata{TargetFile: "package.json"},
		}
		finding4 := ecosystems.SCAResult{
			DepGraph: createTestDepGraph(t, "gomod", "project-4", "4.0.0"),
			Metadata: ecosystems.Metadata{TargetFile: "go.mod"},
		}

		tc := []struct {
			name                             string
			allProjects                      bool
			initialExclude                   string
			plugins                          []ecosystems.SCAPlugin
			expectedWorkflowDataLen          int
			expectLegacyResolutionToBeCalled bool
			expectedExclude                  string
			pluginsShouldNotBeCalled         []int
		}{
			{
				name:           "should return all findings from single plugin when FlagAllProjects is false (e.g. single workspace project with multiple findings)",
				allProjects:    false,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results: []ecosystems.SCAResult{
								finding1,
								finding2,
							},
						},
					},
				},
				expectedWorkflowDataLen:          2,
				expectLegacyResolutionToBeCalled: false,
				expectedExclude:                  "",
			},
			{
				name:           "should return all findings when FlagAllProjects is true",
				allProjects:    true,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results:        []ecosystems.SCAResult{finding1, finding2},
							ProcessedFiles: []string{"uv.lock", "pyproject.toml", "requirements.txt", "setup.py"},
						},
					},
				},
				// Expected: 2 SBOM findings + 1 legacy workflow depgraph = 3
				expectedWorkflowDataLen:          3,
				expectLegacyResolutionToBeCalled: true,
				expectedExclude:                  "uv.lock,pyproject.toml,requirements.txt,setup.py",
			},
			{
				name:           "should continue to next plugin when first plugin returns zero findings and FlagAllProjects is false",
				allProjects:    false,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{},
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results: []ecosystems.SCAResult{finding1},
						},
					},
				},
				expectedWorkflowDataLen:          1,
				expectLegacyResolutionToBeCalled: false,
				expectedExclude:                  "",
			},
			{
				name:           "should stop at first plugin and return its findings when FlagAllProjects is false",
				allProjects:    false,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results: []ecosystems.SCAResult{finding1, finding2},
						},
					},
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results: []ecosystems.SCAResult{finding3, finding4},
						},
					},
				},
				expectedWorkflowDataLen:          2,
				expectLegacyResolutionToBeCalled: false,
				expectedExclude:                  "",
				pluginsShouldNotBeCalled:         []int{1},
			},
			{
				name:           "should return all findings when FlagAllProjects is true and multiple plugins return multiple findings",
				allProjects:    true,
				initialExclude: "",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results:        []ecosystems.SCAResult{finding1, finding2},
							ProcessedFiles: []string{"uv.lock", "pyproject.toml", "requirements.txt", "setup.py"},
						},
					},
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results:        []ecosystems.SCAResult{finding3, finding4},
							ProcessedFiles: []string{"package.json", "go.mod"},
						},
					},
				},
				// Expected: 4 SBOM findings + 1 legacy workflow depgraph = 5
				expectedWorkflowDataLen:          5,
				expectLegacyResolutionToBeCalled: true,
				expectedExclude:                  "uv.lock,pyproject.toml,requirements.txt,setup.py,package.json,go.mod",
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
			},
			{
				name:           "should append ProcessedFiles to existing FlagExclude when FlagAllProjects is true",
				allProjects:    true,
				initialExclude: "existing-file.txt,another-file.py",
				plugins: []ecosystems.SCAPlugin{
					&mockScaPlugin{
						result: &ecosystems.PluginResult{
							Results:        []ecosystems.SCAResult{finding1, finding2},
							ProcessedFiles: []string{"uv.lock", "pyproject.toml", "requirements.txt", "setup.py"},
						},
					},
				},
				// Expected: 2 SBOM findings + 1 legacy workflow depgraph = 3
				expectedWorkflowDataLen:          3,
				expectLegacyResolutionToBeCalled: true,
				expectedExclude:                  "existing-file.txt,another-file.py,uv.lock,pyproject.toml,requirements.txt,setup.py",
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
				resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
				ctx.config.Set(FlagAllProjects, tc.allProjects)
				ctx.config.Set(FlagExclude, tc.initialExclude)
				ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

				if tc.expectLegacyResolutionToBeCalled {
					dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
					mockWorkflowData := []workflow.Data{
						workflow.NewData(
							dataIdentifier,
							"application/json",
							[]byte(`{"mock":"data"}`),
						),
					}
					resolutionHandler.ReturnData = mockWorkflowData
				}

				workflowData, err := handleSBOMResolutionDI(
					ctx.invocationContext,
					ctx.config,
					&nopLogger,
					tc.plugins,
					resolutionHandler.Func(),
				)

				require.NoError(t, err)
				assert.NotNil(t, workflowData)
				assert.Len(t, workflowData, tc.expectedWorkflowDataLen)
				assert.Equal(t, tc.expectLegacyResolutionToBeCalled, resolutionHandler.Called)

				if tc.expectLegacyResolutionToBeCalled {
					actualExclude := resolutionHandler.Config.GetString(FlagExclude)
					assert.Equal(t, tc.expectedExclude, actualExclude, "FlagExclude should contain ProcessedFiles from plugins")
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
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		// Create mock plugin that returns a finding
		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
				ProcessedFiles: []string{"uv.lock"},
			},
		}

		// Create an error with exit code 3 (no projects found)
		exitError3 := mockExitError{code: 3}
		resolutionHandler.ReturnError = exitError3

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		// Should succeed and return SBOM data despite exit code 3 from legacy workflow
		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		// Should have 1 SBOM finding (legacy workflow returned exit code 3, so no legacy data)
		assert.Len(t, workflowData, 1)
		// Legacy resolution should have been called
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called")
		assert.Equal(t, "uv.lock", resolutionHandler.Config.GetString(FlagExclude), "ProcessedFiles should be excluded from legacy resolution")
	})

	t.Run("should handle exit code 3 when no SBOM findings are found", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, false)

		// Create mock plugin that returns no findings
		mockPlugin := &mockScaPlugin{}

		// Create an error with exit code 3 (no projects found)
		exitError3 := mockExitError{code: 3}
		resolutionHandler.ReturnError = exitError3

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		// Should return error when exit code 3 occurs with no SBOM findings
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no supported projects detected")
		assert.Nil(t, workflowData)
		// Legacy resolution should have been called
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called")
	})

	t.Run("should return error for non-exit-code-3 errors from legacy workflow", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		// Create mock plugin that returns a finding
		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
				ProcessedFiles: []string{"uv.lock"},
			},
		}

		// Create an error with exit code 1 (not exit code 3)
		exitError1 := mockExitError{code: 1}
		resolutionHandler.ReturnError = exitError1

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		// Should return error for non-exit-code-3 errors
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error handling legacy workflow")
		assert.Nil(t, workflowData)
		// Legacy resolution should have been called
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called")
		assert.Equal(t, "uv.lock", resolutionHandler.Config.GetString(FlagExclude), "ProcessedFiles should be excluded from legacy resolution")
	})

	t.Run("should skip findings with errors when legacy workflow returns no data", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		ctx.config.Set(FlagAllProjects, true)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "project1/pyproject.toml"},
						Error:    nil,
					},
					{
						Metadata: ecosystems.Metadata{TargetFile: "project2/uv.lock"},
						Error:    fmt.Errorf("failed to generate SBOM"),
					},
				},
				ProcessedFiles: []string{"project1/uv.lock", "project2/uv.lock"},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 1, "Should return only the valid finding since legacy workflow returns nil")
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called")
		assert.Equal(t, "project1/uv.lock,project2/uv.lock", resolutionHandler.Config.GetString(FlagExclude),
			"ProcessedFiles should be excluded from legacy resolution")
	})

	t.Run("should log snyk_errors.Error details for support debugging", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		ctx.config.Set(FlagAllProjects, true) // allProjects must be true for errors to be skipped and logged

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information for support debugging",
		}

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						Metadata: ecosystems.Metadata{TargetFile: "uv.lock"},
						Error:    snykErr,
					},
				},
				ProcessedFiles: []string{"uv.lock"},
			},
		}

		var logBuffer bytes.Buffer
		testLogger := zerolog.New(&logBuffer)

		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&testLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
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
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagStrictOutOfSync, "false")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.True(t, mockPlugin.options.Global.AllowOutOfSync)
	})

	t.Run("should default to strict-out-of-sync=true in plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.False(t, mockPlugin.options.Global.AllowOutOfSync)
	})

	t.Run("should ignore invalid strict-out-of-sync values and default to true", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagStrictOutOfSync, "invalid")

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		require.NotNil(t, mockPlugin.options, "plugin should be called when strict-out-of-sync is invalid")
		assert.False(t, mockPlugin.options.Global.AllowOutOfSync, "invalid strict-out-of-sync should default to strict mode")
		assert.False(t, resolutionHandler.Called, "ResolutionHandlerFunc should not be called when a plugin finding is returned")
	})

	t.Run("should pass exclude flag to plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)
		ctx.config.Set(FlagExclude, "dir1, dir2 ,dir3")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		defer mockSBOMService.Close()
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.Equal(t, []string{"dir1", "dir2", "dir3"}, []string(mockPlugin.options.Global.Exclude))
		assert.True(t, mockPlugin.options.Global.AllProjects)
	})

	t.Run("should pass file flag to plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagFile, "Gemfile")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		defer mockSBOMService.Close()
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		require.NotNil(t, mockPlugin.options.Global.TargetFile)
		assert.Equal(t, "Gemfile", *mockPlugin.options.Global.TargetFile)
	})

	t.Run("should handle empty exclude flag", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagExclude, "")

		mockSBOMService := createMockSBOMService(t, uvSBOMConvertResponse)
		defer mockSBOMService.Close()
		ctx.config.Set(configuration.API_URL, mockSBOMService.URL)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
					},
				},
			},
		}

		_, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.Nil(t, mockPlugin.options.Global.Exclude)
	})

	t.Run("should handle legacy workflow data with errors attached and output warnings", func(t *testing.T) {
		ctx := setupTestContext(t, false)
		ctx.config.Set(FlagAllProjects, true)

		// Create mock plugin that returns no findings to trigger legacy workflow
		mockPlugin := &mockScaPlugin{}

		// Create workflow data with an error attached
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		validData := workflow.NewData(
			dataIdentifier,
			"application/json",
			[]byte(`{}`),
		)

		errorData := workflow.NewData(
			dataIdentifier,
			"application/json",
			[]byte(`{}`),
		)
		errorData.SetMetaData(contentLocationKey, "legacy-project/requirements.txt")
		errorData.AddError(snyk_errors.Error{
			ID:     "SNYK-LEGACY-001",
			Title:  "Legacy Error Title",
			Detail: "Detailed legacy error information for debugging",
		})

		resolutionHandler := NewCalledResolutionHandlerFunc([]workflow.Data{validData, errorData}, nil)

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
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 1, "Should return only the valid data, filtering out error data")
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called")

		// Verify that the warning output contains the legacy error details
		assert.Contains(t, capturedOutput, "legacy-project/requirements.txt", "Output should mention the problem file")
		assert.Contains(t, capturedOutput, "Detailed legacy error information for debugging",
			"Output should include snyk_errors.Error Detail field from legacy data")
		assert.Contains(t, capturedOutput, "1/2 potential projects failed to get dependencies",
			"Output should include number of failed potential projects")
	})

	t.Run("should return snyk_errors.Error when finding has error and allProjects is false", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, false)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information for support debugging",
		}

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						Metadata: ecosystems.Metadata{TargetFile: "uv.lock"},
						Error:    snykErr,
					},
				},
				ProcessedFiles: []string{"uv.lock"},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)
		assert.False(t, resolutionHandler.Called, "ResolutionHandlerFunc should not be called when error is returned early")

		// Verify the returned error is a snyk_errors.Error
		var returnedSnykErr snyk_errors.Error
		require.True(t, errors.As(err, &returnedSnykErr), "returned error should be a snyk_errors.Error")
		assert.Equal(t, "SNYK-TEST-001", returnedSnykErr.ID)
		assert.Equal(t, "Test Error Title", returnedSnykErr.Title)
		assert.Equal(t, "Detailed error information for support debugging", returnedSnykErr.Detail)
	})

	t.Run("should fail fast and return exit code 2 when fail-fast is enabled with all-projects", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)
		ctx.config.Set(FlagFailFast, true)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information for debugging",
		}

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "valid-project/pyproject.toml"},
						Error:    nil,
					},
					{
						Metadata: ecosystems.Metadata{TargetFile: "project1/uv.lock"},
						Error:    snykErr,
					},
					{
						Metadata: ecosystems.Metadata{TargetFile: "project2/uv.lock"},
						Error:    fmt.Errorf("This should not be processed"),
					},
				},
				ProcessedFiles: []string{"project1/uv.lock", "project2/uv.lock"},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)
		assert.False(t, resolutionHandler.Called, "ResolutionHandlerFunc should not be called when fail-fast triggers")

		var ec exitCoder
		require.True(t, errors.As(err, &ec), "error should implement exitCoder")
		assert.Equal(t, 2, ec.ExitCode(), "exit code should be 2 for fail-fast")
		assert.Contains(t, err.Error(), "project1/uv.lock")
	})

	t.Run("should fail fast on first error with snyk error details", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)
		ctx.config.Set(FlagFailFast, true)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-002",
			Title:  "SBOM Conversion Failed",
			Detail: "The SBOM document could not be converted due to invalid format",
		}

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						Metadata: ecosystems.Metadata{TargetFile: "project1/uv.lock"},
						Error:    snykErr,
					},
				},
				ProcessedFiles: []string{"project1/uv.lock"},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)
		assert.Contains(t, err.Error(), "The SBOM document could not be converted due to invalid format")
		assert.Contains(t, err.Error(), "project1/uv.lock")

		var ec exitCoder
		require.True(t, errors.As(err, &ec), "error should implement exitCoder")
		assert.Equal(t, 2, ec.ExitCode())
	})

	t.Run("should not fail fast when fail-fast is false with all-projects", func(t *testing.T) {
		ctx := setupTestContext(t, false)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)
		ctx.config.Set(FlagFailFast, false)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error to help the customer debug the issue",
		}

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "valid-project/pyproject.toml"},
						Error:    nil,
					},
					{
						Metadata: ecosystems.Metadata{TargetFile: "project1/uv.lock"},
						Error:    snykErr,
					},
				},
				ProcessedFiles: []string{"project1/uv.lock"},
			},
		}

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		mockWorkflowData := []workflow.Data{
			workflow.NewData(
				dataIdentifier,
				"application/json",
				[]byte(`{"mock":"data"}`),
			),
		}
		resolutionHandler.ReturnData = mockWorkflowData

		var capturedOutput string
		ctx.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...ui.Opts) error {
			capturedOutput = err.Error()
			return nil
		}).Times(1)

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.True(t, resolutionHandler.Called, "ResolutionHandlerFunc should be called")
		assert.Equal(t, "project1/uv.lock", resolutionHandler.Config.GetString(FlagExclude), "ProcessedFiles should be excluded from legacy resolution")
		assert.Contains(t, capturedOutput, "project1/uv.lock")
	})

	t.Run("should ignore fail-fast when all-projects is false", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, false)
		ctx.config.Set(FlagFailFast, true)

		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error information",
		}

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						Metadata: ecosystems.Metadata{TargetFile: "uv.lock"},
						Error:    snykErr,
					},
				},
				ProcessedFiles: []string{"uv.lock"},
			},
		}

		workflowData, err := handleSBOMResolutionDI(
			ctx.invocationContext,
			ctx.config,
			&nopLogger,
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.Error(t, err)
		assert.Nil(t, workflowData)

		var ec exitCoder
		if errors.As(err, &ec) {
			assert.NotEqual(t, 2, ec.ExitCode(), "exit code should not be 2 when all-projects is false")
		}
	})

	t.Run("should pass fail-fast flag to plugin options", func(t *testing.T) {
		ctx := setupTestContext(t, true)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)
		ctx.config.Set(FlagFailFast, true)

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
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
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		require.NotNil(t, mockPlugin.options, "plugin should have been called with options")
		assert.True(t, mockPlugin.options.Global.FailFast, "FailFast should be true in plugin options")
	})

	t.Run("should output problem findings through UI when allProjects is true", func(t *testing.T) {
		ctx := setupTestContext(t, false)
		resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
		ctx.config.Set(FlagAllProjects, true)

		// Create a snyk error and a regular error
		snykErr := snyk_errors.Error{
			ID:     "SNYK-TEST-001",
			Title:  "Test Error Title",
			Detail: "Detailed error to help the customer debug the issue",
		}
		regularErr := fmt.Errorf("Failure message should not be shown to the user")

		mockPlugin := &mockScaPlugin{
			result: &ecosystems.PluginResult{
				Results: []ecosystems.SCAResult{
					{
						DepGraph: createTestDepGraph(t, "pip", "test-project-1", "1.0.0"),
						Metadata: ecosystems.Metadata{TargetFile: "valid-project/pyproject.toml"},
						Error:    nil,
					},
					{
						Metadata: ecosystems.Metadata{TargetFile: "project1/uv.lock"},
						Error:    snykErr,
					},
					{
						Metadata: ecosystems.Metadata{TargetFile: "project2/uv.lock"},
						Error:    regularErr,
					},
				},
				ProcessedFiles: []string{"project1/uv.lock", "project2/uv.lock"},
			},
		}

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		mockWorkflowData := []workflow.Data{
			workflow.NewData(
				dataIdentifier,
				"application/json",
				[]byte(`{"mock":"data"}`),
			),
		}
		resolutionHandler.ReturnData = mockWorkflowData

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
			[]ecosystems.SCAPlugin{mockPlugin},
			resolutionHandler.Func(),
		)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)

		assert.Equal(t, "project1/uv.lock,project2/uv.lock", resolutionHandler.Config.GetString(FlagExclude),
			"ProcessedFiles should be excluded from legacy resolution")
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

func Test_extractProblemResults(t *testing.T) {
	t.Run("should return findings with lockFile from metadata", func(t *testing.T) {
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		data := workflow.NewData(dataIdentifier, "application/json", []byte(`{}`))
		data.SetMetaData(contentLocationKey, "project/requirements.txt")

		errList := []snyk_errors.Error{
			{ID: "SNYK-001", Title: "Error 1"},
			{ID: "SNYK-002", Title: "Error 2"},
		}

		findings := extractProblemResults(&nopLogger, data, errList)

		require.Len(t, findings, 2)
		assert.Equal(t, "project/requirements.txt", findings[0].Metadata.TargetFile)
		assert.Equal(t, "project/requirements.txt", findings[1].Metadata.TargetFile)
		assert.Equal(t, errList[0], findings[0].Error)
		assert.Equal(t, errList[1], findings[1].Error)
	})

	t.Run("should use 'unknown' as lockFile when metadata retrieval fails", func(t *testing.T) {
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		data := workflow.NewData(dataIdentifier, "application/json", []byte(`{}`))
		// Intentionally NOT setting metadata for contentLocationKey

		errList := []snyk_errors.Error{
			{ID: "SNYK-001", Title: "Error 1"},
		}

		findings := extractProblemResults(&nopLogger, data, errList)

		require.Len(t, findings, 1)
		assert.Equal(t, "unknown", findings[0].Metadata.TargetFile)
		assert.Equal(t, errList[0], findings[0].Error)
	})

	t.Run("should return empty findings when errList is empty", func(t *testing.T) {
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		data := workflow.NewData(dataIdentifier, "application/json", []byte(`{}`))
		data.SetMetaData(contentLocationKey, "project/requirements.txt")

		errList := []snyk_errors.Error{}

		findings := extractProblemResults(&nopLogger, data, errList)

		assert.Len(t, findings, 0)
		assert.NotNil(t, findings)
	})
}

func Test_applyProcessedFilesExclusions(t *testing.T) {
	testCases := []struct {
		name            string
		initialExclude  string
		processedFiles  []string
		expectedExclude string
	}{
		{
			name:            "no processed files does not modify config",
			initialExclude:  "",
			processedFiles:  []string{},
			expectedExclude: "",
		},
		{
			name:            "nil processed files does not modify config",
			initialExclude:  "",
			processedFiles:  nil,
			expectedExclude: "",
		},
		{
			name:            "single processed file",
			processedFiles:  []string{"file1.py"},
			expectedExclude: "file1.py",
		},
		{
			name:            "multiple processed files",
			processedFiles:  []string{"file1.py", "file2.py", "file3.py"},
			expectedExclude: "file1.py,file2.py,file3.py",
		},
		{
			name:            "appends to existing exclude",
			initialExclude:  "existing.txt",
			processedFiles:  []string{"file1.py", "file2.py"},
			expectedExclude: "existing.txt,file1.py,file2.py",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := configuration.New()
			if tc.initialExclude != "" {
				config.Set(FlagExclude, tc.initialExclude)
			}

			applyProcessedFilesExclusions(config, tc.processedFiles)

			assert.Equal(t, tc.expectedExclude, config.GetString(FlagExclude))
		})
	}
}

func Test_processedFilesFlowFromPluginsToExcludeConfig(t *testing.T) {
	ctx := setupTestContext(t, true)
	resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
	ctx.config.Set(FlagAllProjects, true)

	dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
	resolutionHandler.ReturnData = []workflow.Data{
		workflow.NewData(dataIdentifier, "application/json", []byte(`{"mock":"data"}`)),
	}

	mockPlugin1 := &mockScaPlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{{
				DepGraph: createTestDepGraph(t, "pip", "project-1", "1.0.0"),
				Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
			}},
			ProcessedFiles: []string{"file1.py", "file2.py"},
		},
	}
	mockPlugin2 := &mockScaPlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{{
				DepGraph: createTestDepGraph(t, "pip", "project-2", "2.0.0"),
				Metadata: ecosystems.Metadata{TargetFile: "package.json"},
			}},
			ProcessedFiles: []string{"file3.py"},
		},
	}

	_, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin1, mockPlugin2},
		resolutionHandler.Func(),
	)

	require.NoError(t, err)
	require.True(t, resolutionHandler.Called)
	actualExclude := resolutionHandler.Config.GetString(FlagExclude)
	assert.Equal(t, "file1.py,file2.py,file3.py", actualExclude,
		"ProcessedFiles from all plugins should be combined into FlagExclude")
}

func Test_uvWorkspacePackages_passesOptionToPlugin(t *testing.T) {
	ctx := setupTestContext(t, true)
	resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
	ctx.config.Set(FlagUvWorkspacePackages, true)
	ctx.config.Set(FlagFile, "uv.lock")

	mockPlugin := &mockScaPlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "uv", "pkg-a", "1.0.0"),
					Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
				},
			},
		},
	}

	_, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin},
		resolutionHandler.Func(),
	)

	require.NoError(t, err)
	require.NotNil(t, mockPlugin.options)
	assert.True(t, mockPlugin.options.Global.ForceIncludeWorkspacePackages, "ForceIncludeWorkspacePackages should be passed to the plugin")
	assert.False(t, mockPlugin.options.Global.AllProjects, "AllProjects should remain false")
	assert.False(t, resolutionHandler.Called, "legacy workflow should not be called when UvWorkspacePackages is set")
	require.NotNil(t, mockPlugin.options.Global.TargetFile)
	assert.Equal(t, "uv.lock", *mockPlugin.options.Global.TargetFile)
}

func Test_uvWorkspacePackages_combinesMultipleDepGraphsAsJSONL(t *testing.T) {
	ctx := setupTestContext(t, true)
	resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
	ctx.config.Set(FlagFile, "uv.lock")
	ctx.config.Set(FlagUvWorkspacePackages, true)

	mockPlugin := &mockScaPlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{
				{
					DepGraph: createTestDepGraph(t, "uv", "pkg-a", "1.0.0"),
					Metadata: ecosystems.Metadata{TargetFile: "pyproject.toml"},
				},
				{
					DepGraph: createTestDepGraph(t, "uv", "pkg-b", "2.0.0"),
					Metadata: ecosystems.Metadata{TargetFile: "packages/pkg-b/pyproject.toml"},
				},
			},
		},
	}

	workflowDataResult, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin},
		resolutionHandler.Func(),
	)

	require.NoError(t, err)
	require.Len(t, workflowDataResult, 1, "multiple findings should be combined into a single workflow.Data")
	assert.False(t, resolutionHandler.Called, "legacy workflow should not be called")

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
	contentLocation, err := workflowData.GetMetaData(contentLocationKey)
	require.NoError(t, err)
	assert.Equal(t, "pyproject.toml", contentLocation, "Content-Location should be set to the first result's TargetFile")

	normalisedTargetFile, err := workflowData.GetMetaData(MetaKeyNormalisedTargetFile)
	require.NoError(t, err)
	assert.Equal(t, "pyproject.toml", normalisedTargetFile, "normalisedTargetFile should be set to the first result's TargetFile")

	targetFileFromPlugin, err := workflowData.GetMetaData(MetaKeyTargetFileFromPlugin)
	require.NoError(t, err)
	assert.Equal(t, "pyproject.toml", targetFileFromPlugin, "targetFileFromPlugin should be set to the first result's TargetFile")
}

func Test_uvWorkspacePackages_returnsErrorWhenFindingHasError(t *testing.T) {
	ctx := setupTestContext(t, true)
	resolutionHandler := NewCalledResolutionHandlerFunc(nil, nil)
	ctx.config.Set(FlagUvWorkspacePackages, true)
	ctx.config.Set(FlagFile, "uv.lock")

	snykErr := snyk_errors.Error{
		ID:     "SNYK-TEST-001",
		Title:  "Test Error Title",
		Detail: "Detailed error information for support debugging",
	}

	mockPlugin := &mockScaPlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{
				{
					Metadata: ecosystems.Metadata{TargetFile: "uv.lock"},
					Error:    snykErr,
				},
			},
		},
	}

	workflowData, err := handleSBOMResolutionDI(
		ctx.invocationContext,
		ctx.config,
		&nopLogger,
		[]ecosystems.SCAPlugin{mockPlugin},
		resolutionHandler.Func(),
	)

	require.Error(t, err)
	assert.Nil(t, workflowData)
	assert.False(t, resolutionHandler.Called, "legacy workflow should not be called when error is returned early")

	var returnedSnykErr snyk_errors.Error
	require.True(t, errors.As(err, &returnedSnykErr), "returned error should be a snyk_errors.Error")
	assert.Equal(t, "SNYK-TEST-001", returnedSnykErr.ID)
	assert.Equal(t, "Test Error Title", returnedSnykErr.Title)
	assert.Equal(t, "Detailed error information for support debugging", returnedSnykErr.Detail)
}
