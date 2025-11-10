package ecosystems

type ScaPluginOptions struct {
	Global map[string]interface{}
	Python map[string]interface{}
}

// / This should be an actually be a depgraph data type
type Depgraph string

type ScaPlugin interface {
	BuildDepGraphsFromDir(dir string, options ScaPluginOptions) (*Depgraph, error)
}
