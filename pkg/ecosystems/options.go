package ecosystems

import "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"

// SCAPluginOptions contains configuration options for SCA plugins,
// including global settings and language-specific options.
type SCAPluginOptions struct {
	Global GlobalOptions
	Python *PythonOptions
}

// GlobalOptions contains options that apply globally across all SCA plugins.
type GlobalOptions struct {
	TargetFile  *string
	AllProjects bool
	Logger      logger.Logger
}

// PythonOptions contains Python-specific options for dependency graph generation.
type PythonOptions struct {
	NoBuildIsolation bool
	PipenvIncludeDev bool
}

func NewPluginOptions() *SCAPluginOptions {
	return &SCAPluginOptions{
		Global: GlobalOptions{
			Logger: logger.Nop(),
		},
		Python: &PythonOptions{},
	}
}

func (o *SCAPluginOptions) WithTargetFile(targetFile string) *SCAPluginOptions {
	o.Global.TargetFile = &targetFile
	return o
}

func (o *SCAPluginOptions) WithAllProjects(allProjects bool) *SCAPluginOptions {
	o.Global.AllProjects = allProjects
	return o
}

func (o *SCAPluginOptions) WithLogger(l logger.Logger) *SCAPluginOptions {
	o.Global.Logger = l
	return o
}

func (o *SCAPluginOptions) WithNoBuildIsolation(noBuildIsolation bool) *SCAPluginOptions {
	o.Python.NoBuildIsolation = noBuildIsolation
	return o
}

func (o *SCAPluginOptions) WithPipenvIncludeDev(pipenvIncludeDev bool) *SCAPluginOptions {
	o.Python.PipenvIncludeDev = pipenvIncludeDev
	return o
}
