package depgraph

import (
	_ "embed"
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

	t.Run("should support 'debug' flag", func(t *testing.T) {
		// setup
		config.Set(configuration.DEBUG, true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--debug")
	})

	t.Run("should support 'dev' flag", func(t *testing.T) {
		// setup
		config.Set("dev", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--dev")
	})

	t.Run("should support 'fail-fast' flag", func(t *testing.T) {
		// setup
		config.Set("fail-fast", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--fail-fast")
	})

	t.Run("should support 'all-projects' flag", func(t *testing.T) {
		// setup
		config.Set("all-projects", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--all-projects")
	})

	t.Run("should support custom 'targetDirectory'", func(t *testing.T) {
		// setup
		config.Set("targetDirectory", "path/to/target")

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "path/to/target")
	})

	t.Run("should support 'file' flag", func(t *testing.T) {
		// setup
		config.Set("file", "path/to/target/file.js")

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--file=path/to/target/file.js")
	})

	t.Run("should support 'exclude' flag", func(t *testing.T) {
		// setup
		config.Set("exclude", "path/to/target/file.js")

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--exclude=path/to/target/file.js")
	})

	t.Run("should support 'detection-depth' flag", func(t *testing.T) {
		// setup
		config.Set("detection-depth", "42")

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--detection-depth=42")
	})

	t.Run("should support 'prune-repeated-subdependencies' flag", func(t *testing.T) {
		// setup
		config.Set("prune-repeated-subdependencies", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--prune-repeated-subdependencies")
	})

	t.Run("should support 'unmanaged' flag", func(t *testing.T) {
		// setup
		config.Set("unmanaged", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--unmanaged")
	})

	t.Run("should support 'prune-repeated-subdependencies' flag", func(t *testing.T) {
		// setup
		config.Set("prune-repeated-subdependencies", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--prune-repeated-subdependencies")
	})

	t.Run("should support 'scan-unmanaged' flag", func(t *testing.T) {
		// setup
		config.Set("scan-unmanaged", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--scan-unmanaged")
	})

	t.Run("should support 'scan-all-unmanaged' flag", func(t *testing.T) {
		// setup
		config.Set("scan-all-unmanaged", true)

		dataIdentifier := workflow.NewTypeIdentifier(WorkflowID, "depgraph")
		data := workflow.NewData(dataIdentifier, "application/json", []byte(payload))

		// engine mocks
		id := workflow.NewWorkflowIdentifier("legacycli")
		engineMock.EXPECT().InvokeWithConfig(id, config).Return([]workflow.Data{data}, nil).Times(1)

		// execute
		_, err := callback(invocationContextMock, []workflow.Data{})

		// assert
		assert.Nil(t, err)

		commandArgs := config.Get(configuration.RAW_CMD_ARGS)
		assert.Contains(t, commandArgs, "--scan-all-unmanaged")
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
