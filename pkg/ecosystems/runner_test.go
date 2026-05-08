package ecosystems

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

type fakeRunnerPlugin struct {
	name   string
	result *PluginResult
	err    error
	called bool
}

func (f *fakeRunnerPlugin) GetName() string { return f.name }

func (f *fakeRunnerPlugin) BuildDepGraphsFromDir(
	_ context.Context, _ logger.Logger, _ string, _ *SCAPluginOptions,
) (*PluginResult, error) {
	f.called = true
	return f.result, f.err
}

func TestRunPluginsSequentially_ReturnsAnnotatedResultsInOrder(t *testing.T) {
	first := &fakeRunnerPlugin{
		name:   "first",
		result: &PluginResult{Results: []SCAResult{{}, {}}, ProcessedFiles: []string{"a.lock"}},
	}
	second := &fakeRunnerPlugin{
		name:   "second",
		result: &PluginResult{Results: []SCAResult{{}}, ProcessedFiles: []string{"b.lock"}},
	}

	opts := *NewPluginOptions().WithAllProjects(true)
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first, second})

	require.NoError(t, err)
	assert.Nil(t, ff)
	require.Len(t, outcomes, 2)
	assert.Equal(t, "first", outcomes[0].Plugin.GetName())
	assert.Equal(t, "second", outcomes[1].Plugin.GetName())
	assert.Equal(t, []string{"a.lock"}, outcomes[0].ProcessedFiles)
	assert.Equal(t, []string{"b.lock"}, outcomes[1].ProcessedFiles)
}

func TestRunPluginsSequentially_StopsAfterFirstResultsWhenNotAllProjects(t *testing.T) {
	first := &fakeRunnerPlugin{
		name:   "first",
		result: &PluginResult{Results: []SCAResult{{}}},
	}
	second := &fakeRunnerPlugin{name: "second"}

	opts := *NewPluginOptions() // AllProjects=false
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first, second})

	require.NoError(t, err)
	assert.Nil(t, ff)
	assert.Len(t, outcomes, 1, "second plugin must not run when first returned results and !allProjects")
	assert.False(t, second.called, "second plugin must not be invoked")
}

func TestRunPluginsSequentially_RunsAllWhenAllProjects(t *testing.T) {
	first := &fakeRunnerPlugin{
		name:   "first",
		result: &PluginResult{Results: []SCAResult{{}}},
	}
	second := &fakeRunnerPlugin{
		name:   "second",
		result: &PluginResult{Results: []SCAResult{{}}},
	}

	opts := *NewPluginOptions().WithAllProjects(true)
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first, second})

	require.NoError(t, err)
	assert.Nil(t, ff)
	require.Len(t, outcomes, 2)
	assert.True(t, second.called, "second plugin should run when allProjects is set")
}

func TestRunPluginsSequentially_SkipsNilPluginResultButContinues(t *testing.T) {
	first := &fakeRunnerPlugin{name: "first"} // returns nil result
	second := &fakeRunnerPlugin{
		name:   "second",
		result: &PluginResult{Results: []SCAResult{{}}},
	}

	opts := *NewPluginOptions().WithAllProjects(true)
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first, second})

	require.NoError(t, err)
	assert.Nil(t, ff)
	require.Len(t, outcomes, 1)
	assert.Equal(t, "second", outcomes[0].Plugin.GetName())
}

func TestRunPluginsSequentially_PluginInvocationErrorReturnedUnwrappedAndAborts(t *testing.T) {
	pluginErr := errors.New("plugin boom")
	first := &fakeRunnerPlugin{name: "first", err: pluginErr}
	second := &fakeRunnerPlugin{name: "second", result: &PluginResult{Results: []SCAResult{{}}}}

	opts := *NewPluginOptions().WithAllProjects(true)
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first, second})

	require.Error(t, err)
	assert.Same(t, pluginErr, err, "plugin error must be returned unwrapped so os-flows can detect ErrorCatalog content")
	assert.Nil(t, outcomes)
	assert.Nil(t, ff)
	assert.False(t, second.called, "second plugin must not run after a plugin invocation error")
}

func TestRunPluginsSequentially_FailFastTriggersOnPerResultErrorWhenAllProjectsAndFailFast(t *testing.T) {
	failing := SCAResult{Error: errors.New("resolve failed")}
	first := &fakeRunnerPlugin{
		name:   "first",
		result: &PluginResult{Results: []SCAResult{{}, failing}},
	}
	second := &fakeRunnerPlugin{name: "second", result: &PluginResult{Results: []SCAResult{{}}}}

	opts := *NewPluginOptions().WithAllProjects(true).WithFailFast(true)
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first, second})

	require.NoError(t, err)
	require.NotNil(t, ff)
	assert.EqualError(t, ff.Error, "resolve failed")
	assert.Empty(t, outcomes, "outcomes must not include the plugin whose result triggered fail-fast")
	assert.False(t, second.called, "second plugin must not run after fail-fast")
}

func TestRunPluginsSequentially_ErroredResultsFlowThroughWhenFailFastOff(t *testing.T) {
	failing := SCAResult{Error: errors.New("resolve failed")}
	first := &fakeRunnerPlugin{
		name:   "first",
		result: &PluginResult{Results: []SCAResult{{}, failing}},
	}

	opts := *NewPluginOptions().WithAllProjects(true) // FailFast=false
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first})

	require.NoError(t, err)
	assert.Nil(t, ff, "fail-fast must not trigger when FailFast is off")
	require.Len(t, outcomes, 1)
	assert.Len(t, outcomes[0].Results, 2,
		"errored results must be included in the outcome so callers can render warnings")
}

func TestRunPluginsSequentially_FailFastIgnoredWithoutAllProjects(t *testing.T) {
	failing := SCAResult{Error: errors.New("resolve failed")}
	first := &fakeRunnerPlugin{
		name:   "first",
		result: &PluginResult{Results: []SCAResult{failing}},
	}

	opts := *NewPluginOptions().WithFailFast(true) // AllProjects=false
	outcomes, ff, err := RunPluginsSequentially(t.Context(), logger.Nop(), ".", opts, []SCAPlugin{first})

	require.NoError(t, err)
	assert.Nil(t, ff, "fail-fast must not trigger without --all-projects")
	require.Len(t, outcomes, 1)
}
