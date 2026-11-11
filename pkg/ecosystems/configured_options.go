package ecosystems

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
)

// NewPluginOptionsFromConfig preserves raw CLI selectors unless configuration
// explicitly overrides them.
func NewPluginOptionsFromConfig(config configuration.Configuration) (*SCAPluginOptions, error) {
	opts, err := NewPluginOptionsFromRawFlags(config.GetStringSlice(configuration.RAW_CMD_ARGS))
	if err != nil {
		return nil, err
	}

	if err := applyConfiguredPluginFlags(config, opts); err != nil {
		return nil, err
	}

	return opts, nil
}

// Absent config must not erase selectors parsed from the original CLI arguments.
func applyConfiguredPluginFlags(config configuration.Configuration, opts *SCAPluginOptions) error {
	applyConfiguredFlags(config, config.GetBool, []configuredFlag[bool]{
		{workflow.FlagAllProjects, &opts.Global.AllProjects},
		{workflow.FlagUvWorkspacePackages, &opts.Global.ForceIncludeWorkspacePackages},
		{workflow.FlagDev, &opts.Global.IncludeDev},
		{workflow.FlagFailFast, &opts.Global.FailFast},
		{workflow.FlagForceSingleGraph, &opts.Global.ForceSingleGraph},
		{workflow.FlagIncludeProvenance, &opts.Global.IncludeProvenance},
		{workflow.FlagNugetAssetsProjectName, &opts.Dotnet.AssetsProjectName},
		{workflow.FlagAllSubProjects, &opts.Gradle.AllSubProjects},
		{workflow.FlagGradleNormalizeDeps, &opts.Gradle.NormalizeDeps},
	})
	applyConfiguredFlags(config, config.GetString, []configuredFlag[string]{
		{workflow.FlagConfigurationMatching, &opts.Gradle.ConfigurationMatching},
		{workflow.FlagConfigurationAttributes, &opts.Gradle.ConfigurationAttributes},
		{workflow.FlagInitScript, &opts.Gradle.InitScript},
		{workflow.FlagDotnetTargetFramework, &opts.Dotnet.TargetFramework},
		{workflow.FlagNugetPkgsFolder, &opts.Dotnet.PackagesFolder},
	})
	if config.IsSet(workflow.FlagGradleSubProject) {
		opts.Gradle.SubProject = config.GetString(workflow.FlagGradleSubProject)
	} else if config.IsSet(workflow.FlagSubProject) {
		opts.Gradle.SubProject = config.GetString(workflow.FlagSubProject)
	}
	if config.IsSet(workflow.FlagStrictOutOfSync) {
		strict, err := strconv.ParseBool(config.GetString(workflow.FlagStrictOutOfSync))
		opts.Global.AllowOutOfSync = err == nil && !strict
	}
	if config.IsSet(workflow.FlagExclude) {
		opts.Global.Exclude = parseExcludeFlag(config.GetString(workflow.FlagExclude))
	}
	if config.IsSet(workflow.FlagExcludePaths) {
		opts.Global.ExcludePaths = parseExcludeFlag(config.GetString(workflow.FlagExcludePaths))
	}
	if file := config.GetString(workflow.FlagFile); file != "" {
		opts.WithTargetFile(file)
	}
	if config.IsSet(workflow.FlagDetectionDepth) {
		depth, err := ParseDetectionDepth(config.GetString(workflow.FlagDetectionDepth))
		if err != nil {
			return err
		}
		opts.WithDetectionDepth(depth)
	}

	// The CLI resolves --packages-folder from the working directory.
	if packagesFolder := opts.Dotnet.PackagesFolder; packagesFolder != "" {
		if abs, err := filepath.Abs(packagesFolder); err == nil {
			opts.WithPackagesFolder(abs)
		}
	}
	return nil
}

type configuredFlag[T any] struct {
	key    string
	target *T
}

func applyConfiguredFlags[T any](config configuration.Configuration, get func(string) T, flags []configuredFlag[T]) {
	for _, flag := range flags {
		if config.IsSet(flag.key) {
			*flag.target = get(flag.key)
		}
	}
}

// parseExcludeFlag parses a comma-separated exclude flag value into a slice of strings.
func parseExcludeFlag(excludeFlag string) []string {
	if excludeFlag == "" {
		return nil
	}
	parts := strings.Split(excludeFlag, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
