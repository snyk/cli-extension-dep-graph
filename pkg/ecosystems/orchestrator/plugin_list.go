package orchestrator

import "github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"

// PluginList preserves scanner order while allowing callers to compose resolvers.
type PluginList []ecosystems.SCAPlugin

// With owns a new slice so branches cannot overwrite one another's plugins.
func (p PluginList) With(plugins ...ecosystems.SCAPlugin) PluginList {
	combined := make(PluginList, 0, len(p)+len(plugins))
	combined = append(combined, p...)
	return append(combined, plugins...)
}
