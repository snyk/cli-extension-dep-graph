package orchestrator

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

func TestPluginRegistry_PluginsOnlyReadsRegisteredPlugins(t *testing.T) {
	plugin := &mockPlugin{name: "native"}
	cases := []struct {
		name    string
		plugins []ecosystems.SCAPlugin
	}{
		{name: "empty registry"},
		{name: "registered plugin identity", plugins: []ecosystems.SCAPlugin{plugin}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			registry := &PluginRegistry{plugins: tt.plugins}

			plugins := registry.Plugins()

			require.Len(t, plugins, len(tt.plugins))
			for i := range tt.plugins {
				assert.Same(t, tt.plugins[i], plugins[i])
			}
			if len(plugins) > 0 {
				plugins[0] = &mockPlugin{name: "replacement"}
				assert.Same(t, plugin, registry.Plugins()[0])
			}
		})
	}
}

func TestNewPluginRegistry_RegistersCompleteExecutionOrder(t *testing.T) {
	cases := []struct {
		name  string
		flags []flag
		want  []string
	}{
		{name: "legacy only", want: []string{"legacycli"}},
		{name: "UV without native", flags: []flag{FlagUvResolver}, want: []string{"uv", "legacycli"}},
		{name: "native without bazel", flags: []flag{FlagCargoResolver, FlagUvResolver}, want: []string{"cargo", "uv", "legacycli"}},
		{
			name: "all scanners", flags: []flag{
				FlagBazelResolver, FlagBunResolver, FlagPnpmResolver, FlagNewGradleResolver, FlagCargoResolver, FlagDotnetResolver, FlagUvResolver,
			},
			want: []string{"bazel", "bun", "pnpm", "gradle", "cargo", "dotnet", "uv", "legacycli"},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ictx := setupMockInvocationContextWithConfig(t, func(cfg configuration.Configuration) {
				for _, feature := range tt.flags {
					cfg.Set(feature.Key, true)
				}
			})

			registry, err := NewDefaultPluginRegistry(ictx)

			require.NoError(t, err)
			require.Len(t, registry.entries, len(tt.want))
			firstRead := registry.Plugins()
			require.Len(t, firstRead, len(tt.want))
			for i, plugin := range firstRead {
				assert.Equal(t, tt.want[i], plugin.GetName())
				assert.Equal(t, registry.plugins[i], plugin)
				if plugin.GetName() != "uv" && plugin.GetName() != "legacycli" {
					assert.IsType(t, nativePlugin{}, plugin)
				} else {
					_, wrapped := plugin.(nativePlugin)
					assert.False(t, wrapped)
				}
			}
			for _, feature := range tt.flags {
				ictx.GetConfiguration().Set(feature.Key, false)
			}
			assert.Equal(t, firstRead, registry.Plugins())
			firstRead[0] = &mockPlugin{name: "replacement"}
			assert.Equal(t, tt.want[0], registry.Plugins()[0].GetName())
			assert.Len(t, registry.entries, len(tt.want))
		})
	}
}
