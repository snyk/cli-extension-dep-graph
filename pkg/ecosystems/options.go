package ecosystems

// ScaPluginOptions contains configuration options for SCA plugins,
// including global settings and language-specific options.
type ScaPluginOptions struct {
	Global GlobalOptions
	Python *PythonOptions
}

// GlobalOptions contains options that apply globally across all SCA plugins.
type GlobalOptions struct {
	TargetFile     *string
	AllSubProjects bool
}

// PythonOptions contains Python-specific options for dependency graph generation.
type PythonOptions struct{}

func NewPluginOptions() *ScaPluginOptions {
	return &ScaPluginOptions{
		Global: GlobalOptions{},
		Python: &PythonOptions{},
	}
}

func (o *ScaPluginOptions) WithTargetFile(targetFile string) *ScaPluginOptions {
	o.Global.TargetFile = &targetFile
	return o
}

func (o *ScaPluginOptions) WithAllSubProjects(allSubProjects bool) *ScaPluginOptions {
	o.Global.AllSubProjects = allSubProjects
	return o
}
