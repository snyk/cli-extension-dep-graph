package depgraph

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/legacy_cli_output
var payload string

//go:embed testdata/expected_dep_graph.json
var expectedDepGraph string

func Test_callback(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	config := configuration.New()
	// setup mocks
	ctrl := gomock.NewController(t)
	engineMock := mocks.NewMockEngine(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)

	// invocation context mocks
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()

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
			value:    true,
			expected: "--skip-unresolved",
		},
		{
			key:      FlagPythonPackageManager,
			value:    "pip",
			expected: "--package-manager=pip",
		},
	}

	for _, tc := range options {
		t.Run(fmt.Sprintf("flag: %s", tc.key), func(t *testing.T) {
			config.Set(tc.key, tc.value)
			testCmdArgs := invokeWithConfigAndGetTestCmdArgs(t, engineMock, config, invocationContextMock)
			assert.Contains(t, testCmdArgs, tc.expected)
		})
	}

	t.Run("should return a depGraphList", func(t *testing.T) {
		// setup
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))
		engineMock.
			EXPECT().
			InvokeWithConfig(legacyWorkflowID, config).
			Return([]workflow.Data{data}, nil).
			Times(1)

		depGraphs, err := callback(invocationContextMock, []workflow.Data{})
		require.Nil(t, err)

		assert.Len(t, depGraphs, 1)

		actualDepGraph := depGraphs[0].GetPayload().([]byte)

		assert.JSONEq(t, expectedDepGraph, string(actualDepGraph))
	})

	t.Run("should error if no dependency graphs found", func(t *testing.T) {
		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte{})

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.ErrorIs(t, err, errNoDepGraphsFound)
	})
}

func invokeWithConfigAndGetTestCmdArgs(t *testing.T, engineMock *mocks.MockEngine, config configuration.Configuration, invocationContextMock *mocks.MockInvocationContext) interface{} {
	dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
	data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

	// engine mocks
	id := workflow.NewWorkflowIdentifier("legacycli")
	engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

	// execute
	_, err := callback(invocationContextMock, []workflow.Data{})

	// assert
	assert.Nil(t, err)
	return config.Get(configuration.RAW_CMD_ARGS)
}
