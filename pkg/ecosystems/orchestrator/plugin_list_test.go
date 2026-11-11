package orchestrator

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

func TestPluginRegistry_NativePluginsOnly(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "flags disabled"
		if enabled {
			name = "flags enabled"
		}
		t.Run(name, func(t *testing.T) {
			ictx := setupMockInvocationContextWithConfig(t, func(cfg configuration.Configuration) {
				for _, flag := range []flag{FlagBazelResolver, FlagBunResolver, FlagPnpmResolver, FlagNewGradleResolver, FlagCargoResolver, FlagDotnetResolver} {
					cfg.Set(flag.Key, enabled)
				}
			})
			registry, err := NewDefaultPluginRegistry(ictx)
			require.NoError(t, err)

			plugins := registry.Plugins()

			want := []string{}
			if enabled {
				want = []string{"bazel", "bun", "pnpm", "gradle", "cargo", "dotnet"}
			}
			assert.Equal(t, want, listNames(plugins))
		})
	}
}

func listNames(plugins []ecosystems.SCAPlugin) []string {
	names := make([]string, len(plugins))
	for i, plugin := range plugins {
		names[i] = plugin.GetName()
	}
	return names
}

func TestPluginList_WithPreservesBranches(t *testing.T) {
	for _, tt := range []struct {
		name     string
		capacity int
	}{
		{name: "full backing slice", capacity: 1},
		{name: "spare backing capacity", capacity: 8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := make(PluginList, 1, tt.capacity)
			base[0] = &mockPlugin{name: "native"}
			uv := &mockPlugin{name: "uv"}
			legacy := &mockPlugin{name: "legacycli"}

			uvBranch := base.With(uv)
			legacyBranch := base.With(legacy)
			chain := uvBranch.With(legacy)

			assert.Equal(t, []string{"native"}, listNames(base))
			assert.Equal(t, []string{"native", "uv"}, listNames(uvBranch))
			assert.Equal(t, []string{"native", "legacycli"}, listNames(legacyBranch))
			assert.Equal(t, []string{"native", "uv", "legacycli"}, listNames(chain))
			chain[0] = &mockPlugin{name: "changed"}
			assert.Equal(t, "native", base[0].GetName())
			assert.Equal(t, "native", uvBranch[0].GetName())
			assert.Equal(t, "native", legacyBranch[0].GetName())
		})
	}
}

func TestPluginRegistry_PluginsOwnsSlice(t *testing.T) {
	ictx := setupMockInvocationContextWithConfig(t, func(cfg configuration.Configuration) { cfg.Set(FlagCargoResolver.Key, true) })
	registry, err := NewDefaultPluginRegistry(ictx)
	require.NoError(t, err)

	first := registry.Plugins()
	composed := first.With(&mockPlugin{name: "uv"}).With(&mockPlugin{name: "legacycli"})
	first[0] = &mockPlugin{name: "changed"}
	again := registry.Plugins()

	assert.Equal(t, []string{"cargo"}, listNames(again))
	assert.Equal(t, []string{"cargo", "uv", "legacycli"}, listNames(composed))
	assert.Equal(t, []string{"cargo"}, listNames(registry.Plugins()))
}
