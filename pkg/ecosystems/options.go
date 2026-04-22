package ecosystems

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/argparser"
)

// SCAPluginOptions contains configuration options for SCA plugins,
// including global settings and language-specific options.
type SCAPluginOptions struct {
	Global GlobalOptions
	Python PythonOptions
}

// GlobalOptions contains options that apply globally across all SCA plugins.
type GlobalOptions struct {
	TargetFile                    *string              `arg:"--target-file"`
	AllProjects                   bool                 `arg:"--all-projects"`
	IncludeDev                    bool                 `arg:"--dev,-d"`
	Exclude                       CommaSeparatedString `arg:"--exclude"`
	FailFast                      bool                 `arg:"--fail-fast"`
	AllowOutOfSync                bool                 // Derived from --strict-out-of-sync (inverted); parsed in NewPluginOptionsFromRawFlags.
	ForceSingleGraph              bool                 `arg:"--force-single-graph"`
	ForceIncludeWorkspacePackages bool                 `arg:"--internal-uv-workspace-packages"`
	ProjectName                   *string              `arg:"--project-name"`
	RawFlags                      []string
}

// CommaSeparatedString is a custom type that parses comma-separated values.
type CommaSeparatedString []string

// UnmarshalText implements encoding.TextUnmarshaler.
func (c *CommaSeparatedString) UnmarshalText(text []byte) error {
	*c = strings.Split(string(text), ",")
	return nil
}

// PythonOptions contains Python-specific options for dependency graph generation.
type PythonOptions struct {
	NoBuildIsolation bool `arg:"--no-build-isolation"`
}

func NewPluginOptions() *SCAPluginOptions {
	return &SCAPluginOptions{
		Python: PythonOptions{},
	}
}

func NewPluginOptionsFromRawFlags(rawFlags []string) (*SCAPluginOptions, error) {
	var args struct {
		GlobalOptions
		PythonOptions
		StrictOutOfSync *string `arg:"--strict-out-of-sync"`
	}

	if err := argparser.Parse(rawFlags, &args); err != nil {
		return nil, fmt.Errorf("failed to parse raw flags: %w", err)
	}

	args.RawFlags = rawFlags

	if args.StrictOutOfSync != nil {
		if parsed, err := strconv.ParseBool(*args.StrictOutOfSync); err == nil {
			args.AllowOutOfSync = !parsed
		}
	}

	return &SCAPluginOptions{
		Global: args.GlobalOptions,
		Python: args.PythonOptions,
	}, nil
}

func (o *SCAPluginOptions) WithTargetFile(targetFile string) *SCAPluginOptions {
	o.Global.TargetFile = &targetFile
	return o
}

func (o *SCAPluginOptions) WithAllProjects(allProjects bool) *SCAPluginOptions {
	o.Global.AllProjects = allProjects
	return o
}

func (o *SCAPluginOptions) WithNoBuildIsolation(noBuildIsolation bool) *SCAPluginOptions {
	o.Python.NoBuildIsolation = noBuildIsolation
	return o
}

func (o *SCAPluginOptions) WithIncludeDev(includeDev bool) *SCAPluginOptions {
	o.Global.IncludeDev = includeDev
	return o
}

func (o *SCAPluginOptions) WithRawFlags(rawflags string) *SCAPluginOptions {
	o.Global.RawFlags = append(o.Global.RawFlags, rawflags)
	return o
}

func (o *SCAPluginOptions) WithExclude(exclude []string) *SCAPluginOptions {
	o.Global.Exclude = append(o.Global.Exclude, exclude...)
	return o
}

func (o *SCAPluginOptions) WithFailFast(failFast bool) *SCAPluginOptions {
	o.Global.FailFast = failFast
	return o
}

func (o *SCAPluginOptions) WithAllowOutOfSync(allowOutOfSync bool) *SCAPluginOptions {
	o.Global.AllowOutOfSync = allowOutOfSync
	return o
}

func (o *SCAPluginOptions) WithForceSingleGraph(forceSingleGraph bool) *SCAPluginOptions {
	o.Global.ForceSingleGraph = forceSingleGraph
	return o
}

func (o *SCAPluginOptions) WithForceIncludeWorkspacePackages(forceIncludeWorkspacePackages bool) *SCAPluginOptions {
	o.Global.ForceIncludeWorkspacePackages = forceIncludeWorkspacePackages
	return o
}

func (o *SCAPluginOptions) WithProjectName(projectName string) *SCAPluginOptions {
	o.Global.ProjectName = &projectName
	return o
}
