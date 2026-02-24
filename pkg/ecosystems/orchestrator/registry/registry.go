package registry

import (
	"fmt"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// Registry manages registered SCA plugins and their capabilities.
type Registry struct {
	plugins map[string]ecosystems.SCAPlugin
}

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]ecosystems.SCAPlugin),
	}
}

// RegisterPlugin adds a plugin to the registry.
// Plugin names must be unique.
// RegisterPlugin registers a new plugin.
// Registration happens at init time and is not thread-safe.
func (r *Registry) RegisterPlugin(plugin ecosystems.SCAPlugin) error {
	name := plugin.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s is already registered", name)
	}

	r.plugins[name] = plugin

	return nil
}

// Get retrieves a registered plugin by name.
func (r *Registry) Get(name string) (ecosystems.SCAPlugin, bool) {
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// AllPlugins returns all registered plugins.
func (r *Registry) AllPlugins() []ecosystems.SCAPlugin {
	plugins := make([]ecosystems.SCAPlugin, 0, len(r.plugins))
	for _, plugin := range r.plugins {
		plugins = append(plugins, plugin)
	}
	return plugins
}
