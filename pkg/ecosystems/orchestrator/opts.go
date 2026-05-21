package orchestrator

type registerOpt func(*PluginRegistry, *pluginEntry)

func withFeatureFlag(flag flag) registerOpt {
	return func(reg *PluginRegistry, entry *pluginEntry) {
		if reg.ictx.GetConfiguration().GetBool(flag.Key) {
			return
		}
		entry.skip = true
	}
}

func withPluginDependencies(deps ...string) registerOpt {
	return func(_ *PluginRegistry, entry *pluginEntry) {
		entry.dependencies = deps
	}
}
