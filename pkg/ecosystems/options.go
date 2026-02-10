package ecosystems

import "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"

// SCAPluginOptions contains configuration options for SCA plugins,
// including global settings and language-specific options.
type SCAPluginOptions struct {
	GlobalOptions
	PythonOptions
}

// GlobalOptions contains options that apply globally across all SCA plugins.
type GlobalOptions struct {
	TargetFile  *string
	AllProjects bool
	Logger      logger.Logger
	RawFlags    []string
}

// PythonOptions contains Python-specific options for dependency graph generation.
type PythonOptions struct {
	NoBuildIsolation bool
	PipenvIncludeDev bool
}

func NewPluginOptions() *SCAPluginOptions {
	return &SCAPluginOptions{
		GlobalOptions: GlobalOptions{
			Logger: logger.Nop(),
		},
		PythonOptions: PythonOptions{},
	}
}

func (o *SCAPluginOptions) WithTargetFile(targetFile string) *SCAPluginOptions {
	o.TargetFile = &targetFile
	return o
}

func (o *SCAPluginOptions) WithAllProjects(allProjects bool) *SCAPluginOptions {
	o.AllProjects = allProjects
	return o
}

func (o *SCAPluginOptions) WithLogger(l logger.Logger) *SCAPluginOptions {
	o.Logger = l
	return o
}

func (o *SCAPluginOptions) WithNoBuildIsolation(noBuildIsolation bool) *SCAPluginOptions {
	o.NoBuildIsolation = noBuildIsolation
	return o
}

func (o *SCAPluginOptions) WithPipenvIncludeDev(pipenvIncludeDev bool) *SCAPluginOptions {
	o.PipenvIncludeDev = pipenvIncludeDev
	return o
}

func (o *SCAPluginOptions) WithRawFlags(rawFlags []string) *SCAPluginOptions {
	o.RawFlags = rawFlags
	return o
}
