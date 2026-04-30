package orchestrator

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

type mockPlugin struct {
	name           string
	processedFiles []string
	results        []ecosystems.SCAResult
}

func (m mockPlugin) GetName() string {
	return m.name
}

func (m mockPlugin) BuildDepGraphsFromDir(context.Context, logger.Logger, string, *ecosystems.SCAPluginOptions) (*ecosystems.PluginResult, error) {
	return &ecosystems.PluginResult{
		ProcessedFiles: m.processedFiles,
		Results:        m.results,
	}, nil
}

func TestPluginRegistry_OrderPreservedWithoutDependencies(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(mockPlugin{name: "plugin-a"}))
	require.NoError(t, r.register(mockPlugin{name: "plugin-b"}))
	require.NoError(t, r.register(mockPlugin{name: "plugin-c"}))

	require.Len(t, r.plugins, 3)
	assert.Equal(t, "plugin-a", r.plugins[0].GetName())
	assert.Equal(t, "plugin-b", r.plugins[1].GetName())
	assert.Equal(t, "plugin-c", r.plugins[2].GetName())
}

func TestPluginRegistry_DependenciesRespected(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(mockPlugin{name: "plugin-c"}, "plugin-a")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-b"}, "plugin-a")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-a"})
	require.NoError(t, err)

	require.Len(t, r.plugins, 3)
	assert.Equal(t, "plugin-a", r.plugins[0].GetName())
	assert.Equal(t, "plugin-c", r.plugins[1].GetName())
	assert.Equal(t, "plugin-b", r.plugins[2].GetName())
}

func TestPluginRegistry_ChainedDependencies(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(mockPlugin{name: "plugin-c"}, "plugin-b")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-b"}, "plugin-a")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-a"})
	require.NoError(t, err)

	require.Len(t, r.plugins, 3)
	assert.Equal(t, "plugin-a", r.plugins[0].GetName())
	assert.Equal(t, "plugin-b", r.plugins[1].GetName())
	assert.Equal(t, "plugin-c", r.plugins[2].GetName())
}

func TestPluginRegistry_DefaultRegistryOrder(t *testing.T) {
	r, err := NewDefaultPluginRegistry()
	require.NoError(t, err)

	require.Len(t, r.plugins, 4)
	assert.Equal(t, "bun", r.plugins[0].GetName())
	assert.Equal(t, "uv", r.plugins[1].GetName())
	assert.Equal(t, "pip", r.plugins[2].GetName())
	assert.Equal(t, "pipenv", r.plugins[3].GetName())
}

func TestPluginRegistry_DefaultRegistryHasNoCircularDependencies(t *testing.T) {
	// This test ensures NewDefaultPluginRegistry doesn't error due to circular dependencies
	r, err := NewDefaultPluginRegistry()
	require.NoError(t, err, "NewDefaultPluginRegistry should not return error for valid dependency graph")
	assert.NotNil(t, r)
	assert.NotNil(t, r.plugins, "plugins should be successfully sorted without circular dependencies")
	assert.Len(t, r.plugins, 4, "all 4 plugins should be registered")
}

func TestPluginRegistry_CircularDependencyReturnsError(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(mockPlugin{name: "plugin-a"}, "plugin-b")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-b"}, "plugin-a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency detected")
	assert.Contains(t, err.Error(), "plugin-b")
}

func TestPluginRegistry_NonExistentDependencyIgnored(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(mockPlugin{name: "plugin-a"})
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-b"}, "non-existent-plugin")
	require.NoError(t, err)

	require.Len(t, r.plugins, 2)

	pluginNames := make([]string, len(r.plugins))
	for i, p := range r.plugins {
		pluginNames[i] = p.GetName()
	}

	assert.Contains(t, pluginNames, "plugin-a")
	assert.Contains(t, pluginNames, "plugin-b")
}

func TestPluginRegistry_DependencyAddedLater(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(mockPlugin{name: "plugin-b"}, "plugin-a")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-a"})
	require.NoError(t, err)

	require.Len(t, r.plugins, 2)
	assert.Equal(t, "plugin-a", r.plugins[0].GetName())
	assert.Equal(t, "plugin-b", r.plugins[1].GetName())
}

func TestPluginRegistry_CircularDependencyError(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(mockPlugin{name: "plugin-a"}, "plugin-b")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-b"}, "plugin-c")
	require.NoError(t, err)
	err = r.register(mockPlugin{name: "plugin-c"}, "plugin-a")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency detected")
	assert.Contains(t, err.Error(), "plugin-c")
}

func TestPluginRegistry_ResolveDepgraphs_AllProjectsMode(t *testing.T) {
	ictx := setupMockInvocationContext(t)

	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(mockPlugin{
		name:           "plugin-a",
		processedFiles: []string{"file-a.txt"},
		results:        []ecosystems.SCAResult{{ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-a"}}}},
	}))
	require.NoError(t, r.register(mockPlugin{
		name:           "plugin-b",
		processedFiles: []string{"file-b.txt"},
		results:        []ecosystems.SCAResult{{ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-b"}}}},
	}))

	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = true

	resultsChan := r.ResolveDepgraphs(ictx, "/test/dir", opts)

	results := collectResults(resultsChan)

	assert.Len(t, results, 2)
}

func TestPluginRegistry_ResolveDepgraphs_StopsAfterFirstResult(t *testing.T) {
	ictx := setupMockInvocationContext(t)

	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(mockPlugin{
		name:           "plugin-a",
		processedFiles: []string{"file-a.txt"},
		results:        []ecosystems.SCAResult{{ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-a"}}}},
	}))
	require.NoError(t, r.register(mockPlugin{
		name:           "plugin-b",
		processedFiles: []string{"file-b.txt"},
		results:        []ecosystems.SCAResult{{ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-b"}}}},
	}))

	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = false

	resultsChan := r.ResolveDepgraphs(ictx, "/test/dir", opts)

	results := collectResults(resultsChan)

	assert.Len(t, results, 1)
	assert.Equal(t, "type-a", results[0].ProjectDescriptor.Identity.ProjectType)
}

func TestPluginRegistry_ResolveDepgraphs_ContinuesWhenNoResults(t *testing.T) {
	ictx := setupMockInvocationContext(t)

	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(mockPlugin{
		name:           "plugin-a",
		processedFiles: []string{},
		results:        []ecosystems.SCAResult{},
	}))
	require.NoError(t, r.register(mockPlugin{
		name:           "plugin-b",
		processedFiles: []string{"file-b.txt"},
		results:        []ecosystems.SCAResult{{ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-b"}}}},
	}))

	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = false

	resultsChan := r.ResolveDepgraphs(ictx, "/test/dir", opts)

	results := collectResults(resultsChan)

	assert.Len(t, results, 1)
	assert.Equal(t, "type-b", results[0].ProjectDescriptor.Identity.ProjectType)
}

func setupMockInvocationContext(t *testing.T) workflow.InvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	engine := gafmocks.NewMockEngine(ctrl)
	cfg := configuration.New()
	logger := zerolog.Nop()

	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	ictx.EXPECT().Context().Return(context.Background()).AnyTimes()

	engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return([]workflow.Data{}, nil).
		AnyTimes()

	return ictx
}

func collectResults(resultsChan <-chan ecosystems.SCAResult) []ecosystems.SCAResult {
	results := make([]ecosystems.SCAResult, 0)
	for result := range resultsChan {
		results = append(results, result)
	}
	return results
}
