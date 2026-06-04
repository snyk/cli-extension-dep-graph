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

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/identity"
)

type mockPlugin struct {
	name    string
	results []ecosystems.SCAResult

	// capturedExclude / capturedExcludePaths snapshot opts.Global.{Exclude,ExcludePaths}
	// at the moment BuildDepGraphsFromDir is called, so tests can assert on what each
	// plugin saw — distinct from the post-loop state of the live opts pointer, which
	// keeps mutating.
	capturedExclude      []string
	capturedExcludePaths []string
}

func (m *mockPlugin) GetName() string {
	return m.name
}

func (m *mockPlugin) BuildDepGraphsFromDir(
	_ context.Context,
	_ logger.Logger,
	_ string,
	opts *ecosystems.SCAPluginOptions,
	onGraph ecosystems.OnGraphFunc,
) error {
	if opts != nil {
		m.capturedExclude = append([]string(nil), opts.Global.Exclude...)
		m.capturedExcludePaths = append([]string(nil), opts.Global.ExcludePaths...)
	}
	for _, r := range m.results {
		if err := onGraph(r); err != nil {
			return err
		}
	}
	return nil
}

func TestPluginRegistry_OrderPreservedWithoutDependencies(t *testing.T) {
	r := &PluginRegistry{
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(&mockPlugin{name: "plugin-a"}))
	require.NoError(t, r.register(&mockPlugin{name: "plugin-b"}))
	require.NoError(t, r.register(&mockPlugin{name: "plugin-c"}))

	require.Len(t, r.plugins, 3)
	assert.Equal(t, "plugin-a", r.plugins[0].GetName())
	assert.Equal(t, "plugin-b", r.plugins[1].GetName())
	assert.Equal(t, "plugin-c", r.plugins[2].GetName())
}

func TestPluginRegistry_DependenciesRespected(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(&mockPlugin{name: "plugin-c"}, withPluginDependencies("plugin-a"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-b"}, withPluginDependencies("plugin-a"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-a"})
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

	err := r.register(&mockPlugin{name: "plugin-c"}, withPluginDependencies("plugin-b"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-b"}, withPluginDependencies("plugin-a"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-a"})
	require.NoError(t, err)

	require.Len(t, r.plugins, 3)
	assert.Equal(t, "plugin-a", r.plugins[0].GetName())
	assert.Equal(t, "plugin-b", r.plugins[1].GetName())
	assert.Equal(t, "plugin-c", r.plugins[2].GetName())
}

func TestPluginRegistry_DefaultRegistryOrder(t *testing.T) {
	r, err := NewDefaultPluginRegistry(setupMockInvocationContext(t))
	require.NoError(t, err)

	require.Len(t, r.plugins, 0)
}

func TestPluginRegistry_DefaultRegistryOrder_WithFeatureFlags(t *testing.T) {
	ictx := setupMockInvocationContextWithConfig(t, func(cfg configuration.Configuration) {
		cfg.Set(FlagBazelResolver.Key, true)
		cfg.Set(FlagBunResolver.Key, true)
		cfg.Set(FlagNewGradleResolver.Key, true)
	})
	r, err := NewDefaultPluginRegistry(ictx)
	require.NoError(t, err)

	require.Len(t, r.plugins, 3)
	expectedOrder := []string{"bazel", "bun", "gradle"}
	for i, plugin := range r.plugins {
		assert.Equal(t, expectedOrder[i], plugin.GetName())
	}
}

func TestPluginRegistry_DefaultRegistryHasNoCircularDependencies(t *testing.T) {
	// This test ensures NewDefaultPluginRegistry doesn't error due to circular dependencies
	r, err := NewDefaultPluginRegistry(setupMockInvocationContext(t))
	require.NoError(t, err, "NewDefaultPluginRegistry should not return error for valid dependency graph")
	assert.NotNil(t, r)
	assert.NotNil(t, r.plugins, "plugins should be successfully sorted without circular dependencies")
	assert.Len(t, r.plugins, 0, "all 0 plugins should be registered")
}

func TestPluginRegistry_DefaultRegistryHasNoCircularDependencies_WithFeatureFlags(t *testing.T) {
	// This test ensures NewDefaultPluginRegistry doesn't error due to circular dependencies
	ictx := setupMockInvocationContextWithConfig(t, func(cfg configuration.Configuration) {
		cfg.Set(FlagBazelResolver.Key, true)
		cfg.Set(FlagBunResolver.Key, true)
		cfg.Set(FlagNewGradleResolver.Key, true)
	})
	r, err := NewDefaultPluginRegistry(ictx)
	require.NoError(t, err, "NewDefaultPluginRegistry should not return error for valid dependency graph")
	assert.NotNil(t, r)
	assert.NotNil(t, r.plugins, "plugins should be successfully sorted without circular dependencies")
	assert.Len(t, r.plugins, 3, "all 3 plugins should be registered")
}

func TestPluginRegistry_CircularDependencyReturnsError(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(&mockPlugin{name: "plugin-a"}, withPluginDependencies("plugin-b"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-b"}, withPluginDependencies("plugin-a"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency detected")
	assert.Contains(t, err.Error(), "plugin-b")
}

func TestPluginRegistry_NonExistentDependencyIgnored(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(&mockPlugin{name: "plugin-a"})
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-b"}, withPluginDependencies("non-existent-plugin"))
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
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(&mockPlugin{name: "plugin-b"}, withPluginDependencies("plugin-a"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-a"})
	require.NoError(t, err)

	require.Len(t, r.plugins, 2)
	assert.Equal(t, "plugin-a", r.plugins[0].GetName())
	assert.Equal(t, "plugin-b", r.plugins[1].GetName())
}

func TestPluginRegistry_CircularDependencyError(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	err := r.register(&mockPlugin{name: "plugin-a"}, withPluginDependencies("plugin-b"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-b"}, withPluginDependencies("plugin-c"))
	require.NoError(t, err)
	err = r.register(&mockPlugin{name: "plugin-c"}, withPluginDependencies("plugin-a"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "circular dependency detected")
	assert.Contains(t, err.Error(), "plugin-c")
}

func TestPluginRegistry_ResolveDepgraphs_AllProjectsMode(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(&mockPlugin{
		name: "plugin-a",
		results: []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-a"}},
			ProcessedFiles:    []string{"file-a.txt"},
		}},
	}))
	require.NoError(t, r.register(&mockPlugin{
		name: "plugin-b",
		results: []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-b"}},
			ProcessedFiles:    []string{"file-b.txt"},
		}},
	}))

	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = true

	resultsChan := r.ResolveDepgraphs("/test/dir", opts)

	results := collectResults(resultsChan)

	assert.Len(t, results, 2)
}

func TestPluginRegistry_ResolveDepgraphs_StopsAfterFirstResult(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(&mockPlugin{
		name: "plugin-a",
		results: []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-a"}},
			ProcessedFiles:    []string{"file-a.txt"},
		}},
	}))
	require.NoError(t, r.register(&mockPlugin{
		name: "plugin-b",
		results: []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-b"}},
			ProcessedFiles:    []string{"file-b.txt"},
		}},
	}))

	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = false

	resultsChan := r.ResolveDepgraphs("/test/dir", opts)

	results := collectResults(resultsChan)

	assert.Len(t, results, 1)
	assert.Equal(t, "type-a", results[0].ProjectDescriptor.Identity.ProjectType)
}

func TestPluginRegistry_ResolveDepgraphs_ContinuesWhenNoResults(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	require.NoError(t, r.register(&mockPlugin{
		name: "plugin-a",
		// No results — plugin emits nothing through the callback.
	}))
	require.NoError(t, r.register(&mockPlugin{
		name: "plugin-b",
		results: []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-b"}},
			ProcessedFiles:    []string{"file-b.txt"},
		}},
	}))

	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = false

	resultsChan := r.ResolveDepgraphs("/test/dir", opts)

	results := collectResults(resultsChan)

	assert.Len(t, results, 1)
	assert.Equal(t, "type-b", results[0].ProjectDescriptor.Identity.ProjectType)
}

// TestPluginRegistry_ResolveDepgraphs_PropagatesProcessedFilesAsExcludePaths locks in
// that after a plugin returns ProcessedFiles, every subsequent plugin in the chain sees
// those paths on `opts.Global.ExcludePaths` so they can skip already-handled files.
// Processed files are exact paths, not basename patterns, so they belong on the
// ExcludePaths channel rather than the basename-matching Exclude channel.
func TestPluginRegistry_ResolveDepgraphs_PropagatesProcessedFilesAsExcludePaths(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}

	pluginA := &mockPlugin{
		name: "plugin-a",
		results: []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-a"}},
			ProcessedFiles:    []string{"a/lock.json", "a/sub/lock.json"},
		}},
	}
	pluginB := &mockPlugin{
		name: "plugin-b",
		results: []ecosystems.SCAResult{{
			ProjectDescriptor: identity.ProjectDescriptor{Identity: identity.ProjectIdentity{ProjectType: "type-b"}},
			ProcessedFiles:    []string{"b/lock.json"},
		}},
	}
	require.NoError(t, r.register(pluginA))
	require.NoError(t, r.register(pluginB))

	opts := ecosystems.NewPluginOptions()
	opts.Global.AllProjects = true

	collectResults(r.ResolveDepgraphs("/test/dir", opts))

	assert.Empty(t, pluginA.capturedExcludePaths,
		"first plugin sees no ExcludePaths because no plugin has run before it")
	assert.Equal(t, []string{"a/lock.json", "a/sub/lock.json"}, pluginB.capturedExcludePaths,
		"second plugin must see the first plugin's ProcessedFiles on opts.Global.ExcludePaths")
	assert.Empty(t, pluginA.capturedExclude,
		"processed files must NOT leak onto opts.Global.Exclude — that channel is for basename patterns only")
	assert.Empty(t, pluginB.capturedExclude,
		"processed files must NOT leak onto opts.Global.Exclude — that channel is for basename patterns only")
}

func TestPluginRegistry_Register_WithFeatureFlag(t *testing.T) {
	r := &PluginRegistry{
		ictx:    setupMockInvocationContext(t),
		entries: make([]pluginEntry, 0),
		plugins: make([]ecosystems.SCAPlugin, 0),
	}
	// Disable the feature flag
	r.ictx.GetConfiguration().Set("this-ff-is-disabled", false)
	// should get skipped
	pluginA := &mockPlugin{name: "plugin-a"}
	err := r.register(pluginA, withFeatureFlagCheck(flag{Key: "this-ff-is-disabled"}))
	require.NoError(t, err)
	// should get registered
	pluginB := &mockPlugin{name: "plugin-b"}
	err = r.register(pluginB)
	require.NoError(t, err)

	assert.Equal(t, []ecosystems.SCAPlugin{pluginB}, r.plugins, "only registers plugin-b")
}

func setupMockInvocationContext(t *testing.T) workflow.InvocationContext {
	t.Helper()
	return setupMockInvocationContextWithConfig(t, nil)
}

func setupMockInvocationContextWithConfig(t *testing.T, configure func(configuration.Configuration)) workflow.InvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	engine := gafmocks.NewMockEngine(ctrl)
	cfg := configuration.New()
	if configure != nil {
		configure(cfg)
	}
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
