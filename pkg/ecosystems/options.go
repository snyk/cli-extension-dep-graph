package ecosystems

// SCAPluginOptions contains configuration options for SCA plugins,
// including global settings and language-specific options.
type SCAPluginOptions struct {
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

func NewPluginOptions() *SCAPluginOptions {
	return &SCAPluginOptions{
		Global: GlobalOptions{},
		Python: &PythonOptions{},
	}
}

func (o *SCAPluginOptions) WithTargetFile(targetFile string) *SCAPluginOptions {
	o.Global.TargetFile = &targetFile
	return o
}

func (o *SCAPluginOptions) WithAllSubProjects(allSubProjects bool) *SCAPluginOptions {
	o.Global.AllSubProjects = allSubProjects
	return o
}
