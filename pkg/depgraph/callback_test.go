package depgraph

import (
	_ "embed"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-dep-graph/internal/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
	frameworkmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/legacy_cli_output
var payload string

//go:embed testdata/jsonl_output
var jsonlPayload string

//go:embed testdata/expected_dep_graph.json
var expectedDepGraph string

//go:embed testdata/uv-sbom-convert-expected-dep-graph.json
var uvSBOMConvertExpectedDepGraph string

//go:embed testdata/uv-sbom-convert-response.json
var uvSBOMConvertResponse string

const errMsgPayloadShouldBeByte = "payload should be []byte"

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
}

func Test_callback(t *testing.T) {
	nopLogger := zerolog.Nop()
	config := configuration.New()
	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := frameworkmocks.NewMockEngine(ctrl)
	invocationContextMock := frameworkmocks.NewMockInvocationContext(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()

	type option struct {
		key      string
		value    interface{}
		expected string
	}

	options := []option{
		{
			key:      configuration.DEBUG,
			value:    true,
			expected: "--debug",
		},
		{
			key:      FlagDev,
			value:    true,
			expected: "--dev",
		},
		{
			key:      FlagFailFast,
			value:    true,
			expected: "--fail-fast",
		},
		{
			key:      FlagAllProjects,
			value:    true,
			expected: "--all-projects",
		},
		{
			key:      "targetDirectory",
			value:    "path/to/target",
			expected: "path/to/target",
		},
		{
			key:      FlagFile,
			value:    "path/to/target/file.js",
			expected: "--file=path/to/target/file.js",
		},
		{
			key:      "exclude",
			value:    "path/to/target/file.js",
			expected: "--exclude=path/to/target/file.js",
		},
		{
			key:      FlagDetectionDepth,
			value:    "42",
			expected: "--detection-depth=42",
		},
		{
			key:      FlagPruneRepeatedSubdependencies,
			value:    true,
			expected: "--prune-repeated-subdependencies",
		},
		{
			key:      "unmanaged",
			value:    true,
			expected: "--unmanaged",
		},
		{
			key:      FlagScanUnmanaged,
			value:    true,
			expected: "--scan-unmanaged",
		},
		{
			key:      FlagScanAllUnmanaged,
			value:    true,
			expected: "--scan-all-unmanaged",
		},
		{
			key:      FlagSubProject,
			value:    "app",
			expected: "--sub-project=app",
		},
		{
			key:      FlagGradleSubProject,
			value:    "app",
			expected: "--gradle-sub-project=app",
		},
		{
			key:      FlagGradleNormalizeDeps,
			value:    true,
			expected: "--gradle-normalize-deps",
		},
		{
			key:      FlagAllSubProjects,
			value:    true,
			expected: "--all-sub-projects",
		},
		{
			key:      FlagConfigurationMatching,
			value:    "^releaseRuntimeClasspath$",
			expected: "--configuration-matching=^releaseRuntimeClasspath$",
		},
		{
			key:      FlagConfigurationAttributes,
			value:    "buildtype:release,usage:java-runtime",
			expected: "--configuration-attributes=buildtype:release,usage:java-runtime",
		},
		{
			key:      FlagInitScript,
			value:    "/somewhere/init.gradle",
			expected: "--init-script=/somewhere/init.gradle",
		},
		{
			key:      FlagYarnWorkspaces,
			value:    true,
			expected: "--yarn-workspaces",
		},
		{
			key:      FlagPythonCommand,
			value:    "python3",
			expected: "--command=python3",
		},
		{
			key:      FlagPythonSkipUnresolved,
			value:    "true",
			expected: "--skip-unresolved=true",
		},
		{
			key:      FlagPythonPackageManager,
			value:    "pip",
			expected: "--package-manager=pip",
		},
		{
			key:      FlagNPMStrictOutOfSync,
			value:    "false",
			expected: "--strict-out-of-sync=false",
		},
		{
			key:      FlagNugetAssetsProjectName,
			value:    true,
			expected: "--assets-project-name",
		},
		{
			key:      FlagNugetPkgsFolder,
			value:    "../packages",
			expected: "--packages-folder=../packages",
		},
		{
			key:      FlagUnmanagedMaxDepth,
			value:    "42",
			expected: "--max-depth=42",
		},
		{
			key:      FlagDotnetRuntimeResolution,
			value:    true,
			expected: "--dotnet-runtime-resolution",
		},
		{
			key:      FlagDotnetTargetFramework,
			value:    "net9.3",
			expected: "--dotnet-target-framework=net9.3",
		},
	}

	for _, tc := range options {
		t.Run(fmt.Sprintf("flag: %s", tc.key), func(t *testing.T) {
			config.Set(tc.key, tc.value)
			testCmdArgs := invokeWithConfigAndGetTestCmdArgs(t, engineMock, config, invocationContextMock)
			assert.Contains(t, testCmdArgs, tc.expected)
		})
	}

	t.Run("should not include target directory if file flag provided", func(t *testing.T) {
		config.Set(FlagFile, "path/to/target/file.js")
		config.Set("targetDirectory", "path/to/target")

		testCmdArgs := invokeWithConfigAndGetTestCmdArgs(t, engineMock, config, invocationContextMock)

		assert.Contains(t, testCmdArgs, "--file=path/to/target/file.js")
		assert.NotContains(t, testCmdArgs, "path/to/target")
	})

	t.Run("should return a depGraphList", func(t *testing.T) {
		// setup
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		data := workflow.NewData(dataIdentifier, contentTypeJSON, []byte(payload))
		engineMock.
			EXPECT().
			InvokeWithConfig(legacyWorkflowID, config).
			Return([]workflow.Data{data}, nil).
			Times(1)

		depGraphs, err := callback(invocationContextMock, []workflow.Data{})
		require.Nil(t, err)

		assert.Len(t, depGraphs, 1)

		actualDepGraph, ok := depGraphs[0].GetPayload().([]byte)
		require.True(t, ok, errMsgPayloadShouldBeByte)
		assert.JSONEq(t, expectedDepGraph, string(actualDepGraph))
	})

	t.Run("should return effective dep graphs when requested", func(t *testing.T) {
		config.Set(FlagPrintEffectiveGraph, true)
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		data := workflow.NewData(dataIdentifier, contentTypeJSON, []byte(jsonlPayload))
		engineMock.
			EXPECT().
			InvokeWithConfig(legacyWorkflowID, config).
			Return([]workflow.Data{data}, nil).
			Times(1)

		depGraphs, err := callback(invocationContextMock, []workflow.Data{})
		require.Nil(t, err)

		assert.Len(t, depGraphs, 1)

		actualDepGraph, ok := depGraphs[0].GetPayload().([]byte)
		require.True(t, ok, errMsgPayloadShouldBeByte)
		assert.Contains(t, string(actualDepGraph), "npm")

		verifyMeta(t, depGraphs[0], MetaKeyNormalisedTargetFile, "some normalised target file")
		verifyMeta(t, depGraphs[0], MetaKeyTargetFileFromPlugin, "some target file from plugin")
		verifyMeta(t, depGraphs[0], MetaKeyTarget, `{"key":"some target value"}`)
	})

	t.Run("should error if no dependency graphs found", func(t *testing.T) {
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
		data := workflow.NewData(dataIdentifier, contentTypeJSON, []byte{})

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.ErrorIs(t, err, errNoDepGraphsFound)
	})
}

func invokeWithConfigAndGetTestCmdArgs(
	t *testing.T,
	engineMock *frameworkmocks.MockEngine,
	config configuration.Configuration,
	invocationContextMock *frameworkmocks.MockInvocationContext,
) interface{} {
	t.Helper()
	dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, workflowIDStr)
	data := workflow.NewData(dataIdentifier, contentTypeJSON, []byte(payload))

	// engine mocks
	id := workflow.NewWorkflowIdentifier("legacycli")
	engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

	// execute
	_, err := callback(invocationContextMock, []workflow.Data{})

	// assert
	assert.Nil(t, err)
	return config.Get(configuration.RAW_CMD_ARGS)
}

func verifyMeta(t *testing.T, data workflow.Data, key, expectedValue string) {
	t.Helper()

	value, err := data.GetMetaData(key)
	require.NoError(t, err)
	assert.Equal(t, expectedValue, value)
}
