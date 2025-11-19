package depgraph

import (
	_ "embed"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
	"github.com/snyk/go-application-framework/pkg/configuration"
	frameworkmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/uv-sbom-convert-expected-dep-graph.json
var uvSBOMConvertExpectedDepGraph string

//go:embed testdata/uv-sbom-convert-response.json
var uvSBOMConvertResponse string

type mockScaPlugin struct {
	findings []scaplugin.Finding
	err      error
}

func (m *mockScaPlugin) BuildFindingsFromDir(_ string, _ scaplugin.Options, _ *zerolog.Logger) ([]scaplugin.Finding, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.findings, nil
}

func Test_callback_SBOMResolution(t *testing.T) {
	nopLogger := zerolog.Nop()

	t.Run("should return depgraphs from SBOM conversion when use-sbom-resolution flag is enabled", func(t *testing.T) {
		// Create mock SBOM service response with a depGraph fact
		mockResponse := mocks.NewMockResponse(
			"application/json",
			[]byte(uvSBOMConvertResponse),
			http.StatusOK,
		)

		mockSBOMService := mocks.NewMockSBOMService(mockResponse, func(r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.RequestURI, "/hidden/orgs/test-org-id/sboms/convert")
			assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		})
		defer mockSBOMService.Close()

		config := configuration.New()
		config.Set(FlagUseSBOMResolution, true)
		config.Set(configuration.ORGANIZATION, "test-org-id")
		config.Set(configuration.API_URL, mockSBOMService.URL)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engineMock := frameworkmocks.NewMockEngine(ctrl)
		invocationContextMock := frameworkmocks.NewMockInvocationContext(ctrl)

		invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
		invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
		invocationContextMock.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
		invocationContextMock.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()

		// Create mock UV client that returns valid SBOM data
		mockUVClient := &mocks.MockUVClient{
			ExportSBOMFunc: func(_ string) ([]byte, error) {
				// Return a minimal valid CycloneDX SBOM
				return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), nil
			},
		}

		workflowData, err := callbackWithDI(invocationContextMock, []workflow.Data{}, mockUVClient)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		assert.Len(t, workflowData, 1)

		// Compare the workflow data payload with the expected depGraph
		depGraph, ok := workflowData[0].GetPayload().([]byte)
		require.True(t, ok, "payload should be []byte")
		assert.JSONEq(t, uvSBOMConvertExpectedDepGraph, string(depGraph))
	})

	t.Run("should handle UV client errors gracefully", func(t *testing.T) {
		config := configuration.New()
		config.Set(FlagUseSBOMResolution, true)
		config.Set(configuration.ORGANIZATION, "test-org-id")

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engineMock := frameworkmocks.NewMockEngine(ctrl)
		invocationContextMock := frameworkmocks.NewMockInvocationContext(ctrl)

		invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
		invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
		invocationContextMock.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()

		// Create mock UV client that returns an error
		mockUVClient := &mocks.MockUVClient{
			ExportSBOMFunc: func(_ string) ([]byte, error) {
				return nil, fmt.Errorf("uv command failed")
			},
		}

		depGraphs, err := callbackWithDI(invocationContextMock, []workflow.Data{}, mockUVClient)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to export SBOM using uv")
		assert.Nil(t, depGraphs)
	})

	t.Run("should handle SBOM convert network request errors", func(t *testing.T) {
		// Create mock SBOM service response with an error status
		mockResponse := mocks.NewMockResponse(
			"application/json",
			[]byte(`{"message":"Internal server error."}`),
			http.StatusInternalServerError,
		)

		mockSBOMService := mocks.NewMockSBOMService(mockResponse, func(r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.RequestURI, "/hidden/orgs/test-org-id/sboms/convert")
			assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		})
		defer mockSBOMService.Close()

		config := configuration.New()
		config.Set(FlagUseSBOMResolution, true)
		config.Set(configuration.ORGANIZATION, "test-org-id")
		config.Set(configuration.API_URL, mockSBOMService.URL)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engineMock := frameworkmocks.NewMockEngine(ctrl)
		invocationContextMock := frameworkmocks.NewMockInvocationContext(ctrl)

		invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
		invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
		invocationContextMock.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
		invocationContextMock.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()

		// Create mock UV client that returns valid SBOM data
		mockUVClient := &mocks.MockUVClient{
			ExportSBOMFunc: func(_ string) ([]byte, error) {
				// Return a minimal valid CycloneDX SBOM
				return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), nil
			},
		}

		depGraphs, err := callbackWithDI(invocationContextMock, []workflow.Data{}, mockUVClient)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "analysis of SBOM document failed due to error")
		assert.Contains(t, err.Error(), "500")
		assert.Nil(t, depGraphs)
	})

	t.Run("should return error when SBOM conversion fails for any finding when multiple findings are present", func(t *testing.T) {
		// Create mock SBOM service with two responses: first success, second error
		mockResponses := []mocks.MockResponse{
			mocks.NewMockResponse(
				"application/json",
				[]byte(uvSBOMConvertResponse),
				http.StatusOK,
			),
			mocks.NewMockResponse(
				"application/json",
				[]byte(`{"message":"Internal server error."}`),
				http.StatusInternalServerError,
			),
		}

		mockSBOMService := mocks.NewMockSBOMServiceMultiResponse(mockResponses, func(r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.RequestURI, "/hidden/orgs/test-org-id/sboms/convert")
			assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		})
		defer mockSBOMService.Close()

		config := configuration.New()
		config.Set(FlagUseSBOMResolution, true)
		config.Set(FlagAllProjects, true)
		config.Set(configuration.ORGANIZATION, "test-org-id")
		config.Set(configuration.API_URL, mockSBOMService.URL)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engineMock := frameworkmocks.NewMockEngine(ctrl)
		invocationContextMock := frameworkmocks.NewMockInvocationContext(ctrl)

		invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
		invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
		invocationContextMock.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
		invocationContextMock.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()

		// Create mock plugin that returns two findings
		mockPlugin := &mockScaPlugin{
			findings: []scaplugin.Finding{
				{Sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), FilesProcessed: []string{}},
				{Sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"test"}]}`), FilesProcessed: []string{}},
			},
		}

		depGraphs, err := handleSBOMResolution(invocationContextMock, config, &nopLogger, []scaplugin.ScaPlugin{mockPlugin})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "analysis of SBOM document failed due to error")
		assert.Contains(t, err.Error(), "500")
		assert.Nil(t, depGraphs)
	})

	t.Run("should return only first finding when FlagAllProjects is false", func(t *testing.T) {
		// Create mock SBOM service response
		mockResponse := mocks.NewMockResponse(
			"application/json",
			[]byte(uvSBOMConvertResponse),
			http.StatusOK,
		)

		mockSBOMService := mocks.NewMockSBOMService(mockResponse, func(r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Contains(t, r.RequestURI, "/hidden/orgs/test-org-id/sboms/convert")
		})
		defer mockSBOMService.Close()

		config := configuration.New()
		config.Set(FlagUseSBOMResolution, true)
		config.Set(FlagAllProjects, false)
		config.Set(configuration.ORGANIZATION, "test-org-id")
		config.Set(configuration.API_URL, mockSBOMService.URL)

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		engineMock := frameworkmocks.NewMockEngine(ctrl)
		invocationContextMock := frameworkmocks.NewMockInvocationContext(ctrl)

		invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
		invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
		invocationContextMock.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
		invocationContextMock.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()

		// Create mock UV client that returns valid SBOM data
		mockUVClient := &mocks.MockUVClient{
			ExportSBOMFunc: func(_ string) ([]byte, error) {
				return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), nil
			},
		}

		workflowData, err := callbackWithDI(invocationContextMock, []workflow.Data{}, mockUVClient)

		require.NoError(t, err)
		assert.NotNil(t, workflowData)
		// Should only have one finding even if multiple plugins could return findings
		assert.Len(t, workflowData, 1)
	})

	t.Run("handleSBOMResolution with FlagAllProjects", func(t *testing.T) {
		finding1 := scaplugin.Finding{Sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), FilesProcessed: []string{}}
		finding2 := scaplugin.Finding{Sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"test"}]}`), FilesProcessed: []string{}}
		finding3 := scaplugin.Finding{Sbom: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"someFinding"}]}`), FilesProcessed: []string{}}
		finding4 := scaplugin.Finding{
			Sbom:           []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"anotherFinding"}]}`),
			FilesProcessed: []string{},
		}

		tc := []struct {
			name                    string
			allProjects             bool
			plugins                 []scaplugin.ScaPlugin
			expectedWorkflowDataLen int
		}{
			{
				name:        "should return only first finding when FlagAllProjects is false and BuildFindingsFromDir returns 2 findings",
				allProjects: false,
				plugins: []scaplugin.ScaPlugin{
					&mockScaPlugin{
						findings: []scaplugin.Finding{
							finding1,
							finding2,
						},
					},
				},
				expectedWorkflowDataLen: 1,
			},
			{
				name:        "should return all findings when FlagAllProjects is true",
				allProjects: true,
				plugins: []scaplugin.ScaPlugin{
					&mockScaPlugin{
						findings: []scaplugin.Finding{
							finding1,
							finding2,
						},
					},
				},
				expectedWorkflowDataLen: 2,
			},
			{
				name:        "should continue to next plugin when first plugin returns zero findings and FlagAllProjects is false",
				allProjects: false,
				plugins: []scaplugin.ScaPlugin{
					&mockScaPlugin{
						findings: []scaplugin.Finding{},
					},
					&mockScaPlugin{
						findings: []scaplugin.Finding{
							finding1,
						},
					},
				},
				expectedWorkflowDataLen: 1,
			},
			{
				name:        "should return one finding when multiple plugins return multiple findings and FlagAllProjects is false",
				allProjects: false,
				plugins: []scaplugin.ScaPlugin{
					&mockScaPlugin{
						findings: []scaplugin.Finding{
							finding1,
							finding2,
						},
					},
					&mockScaPlugin{
						findings: []scaplugin.Finding{
							finding3,
							finding4,
						},
					},
				},
				expectedWorkflowDataLen: 1,
			},
			{
				name:        "should return all findings when FlagAllProjects is true and multiple plugins return multiple findings",
				allProjects: true,
				plugins: []scaplugin.ScaPlugin{
					&mockScaPlugin{
						findings: []scaplugin.Finding{
							finding1,
							finding2,
						},
					},
					&mockScaPlugin{
						findings: []scaplugin.Finding{
							finding3,
							finding4,
						},
					},
				},
				expectedWorkflowDataLen: 4,
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

				config := configuration.New()
				config.Set(FlagUseSBOMResolution, true)
				config.Set(FlagAllProjects, tc.allProjects)
				config.Set(configuration.ORGANIZATION, "test-org-id")
				config.Set(configuration.API_URL, mockSBOMService.URL)

				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				engineMock := frameworkmocks.NewMockEngine(ctrl)
				invocationContextMock := frameworkmocks.NewMockInvocationContext(ctrl)

				invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
				invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
				invocationContextMock.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()
				invocationContextMock.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()

				workflowData, err := handleSBOMResolution(invocationContextMock, config, &nopLogger, tc.plugins)

				require.NoError(t, err)
				assert.NotNil(t, workflowData)
				assert.Len(t, workflowData, tc.expectedWorkflowDataLen)
			})
		}
	})
}

func Test_getExclusionsFromFindings(t *testing.T) {
	testCases := []struct {
		name     string
		findings []scaplugin.Finding
		expected []string
	}{
		{
			name:     "should return empty slice when findings is empty",
			findings: []scaplugin.Finding{},
			expected: []string{},
		},
		{
			name: "should return empty slice when finding has no files processed",
			findings: []scaplugin.Finding{
				{
					Sbom:           []byte(`{"bomFormat":"CycloneDX"}`),
					FilesProcessed: []string{},
				},
			},
			expected: []string{},
		},
		{
			name: "should return files from single finding",
			findings: []scaplugin.Finding{
				{
					Sbom:           []byte(`{"bomFormat":"CycloneDX"}`),
					FilesProcessed: []string{"file1.py", "file2.py"},
				},
			},
			expected: []string{"file1.py", "file2.py"},
		},
		{
			name: "should return all files from multiple findings",
			findings: []scaplugin.Finding{
				{
					Sbom:           []byte(`{"bomFormat":"CycloneDX"}`),
					FilesProcessed: []string{"file1.py", "file2.py"},
				},
				{
					Sbom:           []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`),
					FilesProcessed: []string{"file3.py", "file4.py", "file5.py"},
				},
			},
			expected: []string{"file1.py", "file2.py", "file3.py", "file4.py", "file5.py"},
		},
		{
			name: "should handle mixed findings with and without files processed",
			findings: []scaplugin.Finding{
				{
					Sbom:           []byte(`{"bomFormat":"CycloneDX"}`),
					FilesProcessed: []string{},
				},
				{
					Sbom:           []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`),
					FilesProcessed: []string{"file1.py"},
				},
				{
					Sbom:           []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`),
					FilesProcessed: []string{"file2.py", "file3.py"},
				},
			},
			expected: []string{"file1.py", "file2.py", "file3.py"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exclusions := getExclusionsFromFindings(tc.findings)
			assert.Equal(t, tc.expected, exclusions)
			// Ensure that even empty results return a non-nil slice
			if len(tc.findings) == 0 {
				assert.NotNil(t, exclusions)
			}
		})
	}
}
