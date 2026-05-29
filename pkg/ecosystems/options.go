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
	Gradle GradleOptions
	Bazel  BazelOptions
}

// GlobalOptions contains options that apply globally across all SCA plugins.
type GlobalOptions struct {
	TargetFile                    *string              `arg:"--target-file"`
	AllProjects                   bool                 `arg:"--all-projects"`
	IncludeDev                    bool                 `arg:"--dev,-d"`
	Exclude                       CommaSeparatedString `arg:"--exclude"`
	ExcludePaths                  CommaSeparatedString `arg:"--exclude-paths"`
	FailFast                      bool                 `arg:"--fail-fast"`
	AllowOutOfSync                bool                 // Derived from --strict-out-of-sync (inverted); parsed in NewPluginOptionsFromRawFlags.
	ForceSingleGraph              bool                 `arg:"--force-single-graph"`
	ForceIncludeWorkspacePackages bool                 `arg:"--internal-uv-workspace-packages"`
	ProjectName                   *string              `arg:"--project-name"`
	IncludeProvenance             bool                 `arg:"--include-provenance"`
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

// GradleOptions contains Gradle-specific options for dependency graph generation.
type GradleOptions struct {
	// ConfigurationMatching is a regex to select only matching Gradle configurations.
	ConfigurationMatching string `arg:"--configuration-matching"`
	// ConfigurationAttributes filters configurations by attribute values (key:value,key:value).
	ConfigurationAttributes string `arg:"--configuration-attributes"`
	// SubProject restricts scanning to a single named Gradle sub-project.
	// Accepts both --gradle-sub-project and --sub-project (legacy alias).
	SubProject string `arg:"--gradle-sub-project,--sub-project"`
	// AllSubProjects scans all sub-projects in a multi-project build.
	AllSubProjects bool `arg:"--all-sub-projects"`
	// InitScript overrides the built-in init script with a user-supplied path.
	InitScript string `arg:"--init-script"`
	// SkipWrapper bypasses gradlew discovery and forces use of the gradle command.
	SkipWrapper bool `arg:"--gradle-skip-wrapper"`
	// NormalizeDeps uses the SHAs of the dependencies provided by the IncludeProvenance flag
	// to lookup the canonical GAV coordinates of the dependency and rewrite the produced DepGraphs.
	NormalizeDeps bool `arg:"--gradle-normalize-deps"`
}

// BazelOptions contains Bazel-specific options for dependency graph generation.
type BazelOptions struct {
	TargetQuery string `arg:"--bazel-target-query"`
	MaxTargets  *int   `arg:"--bazel-max-targets"`
	Jvm         bool   `arg:"--bazel-jvm"`
	Go          bool   `arg:"--bazel-go"`
}

func NewPluginOptions() *SCAPluginOptions {
	return &SCAPluginOptions{
		Python: PythonOptions{},
		Gradle: GradleOptions{},
		Bazel:  BazelOptions{},
	}
}

func NewPluginOptionsFromRawFlags(rawFlags []string) (*SCAPluginOptions, error) {
	var args struct {
		GlobalOptions
		PythonOptions
		GradleOptions
		BazelOptions
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
		Gradle: args.GradleOptions,
		Bazel:  args.BazelOptions,
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

func (o *SCAPluginOptions) WithExcludePaths(excludePaths []string) *SCAPluginOptions {
	o.Global.ExcludePaths = append(o.Global.ExcludePaths, excludePaths...)
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

func (o *SCAPluginOptions) WithGradleConfigurationMatching(pattern string) *SCAPluginOptions {
	o.Gradle.ConfigurationMatching = pattern
	return o
}

func (o *SCAPluginOptions) WithGradleConfigurationAttributes(attributes string) *SCAPluginOptions {
	o.Gradle.ConfigurationAttributes = attributes
	return o
}

func (o *SCAPluginOptions) WithGradleSubProject(subProject string) *SCAPluginOptions {
	o.Gradle.SubProject = subProject
	return o
}

func (o *SCAPluginOptions) WithGradleAllSubProjects(all bool) *SCAPluginOptions {
	o.Gradle.AllSubProjects = all
	return o
}

func (o *SCAPluginOptions) WithGradleInitScript(initScript string) *SCAPluginOptions {
	o.Gradle.InitScript = initScript
	return o
}

func (o *SCAPluginOptions) WithGradleSkipWrapper(skipWrapper bool) *SCAPluginOptions {
	o.Gradle.SkipWrapper = skipWrapper
	return o
}

func (o *SCAPluginOptions) WithGradleNormalizeDeps(normalizeDeps bool) *SCAPluginOptions {
	o.Gradle.NormalizeDeps = normalizeDeps
	return o
}

func (o *SCAPluginOptions) WithIncludeProvenance(includeProvenance bool) *SCAPluginOptions {
	o.Global.IncludeProvenance = includeProvenance
	return o
}

// WithBazelJvm sets whether the Bazel JVM dep-graph scanner should run.
func (o *SCAPluginOptions) WithBazelJvm(b bool) *SCAPluginOptions {
	o.Bazel.Jvm = b
	return o
}

// WithBazelGo sets whether the Bazel Go dep-graph scanner should run.
func (o *SCAPluginOptions) WithBazelGo(b bool) *SCAPluginOptions {
	o.Bazel.Go = b
	return o
}

// WithBazelTargetQuery sets the Bazel query used for target discovery (empty = plugin default).
func (o *SCAPluginOptions) WithBazelTargetQuery(query string) *SCAPluginOptions {
	o.Bazel.TargetQuery = query
	return o
}

// WithBazelMaxTargets caps the number of Bazel targets the resolver will
// process. 0 disables the ceiling. Not calling this leaves the plugin's safe
// default in place.
func (o *SCAPluginOptions) WithBazelMaxTargets(n int) *SCAPluginOptions {
	o.Bazel.MaxTargets = &n
	return o
}
