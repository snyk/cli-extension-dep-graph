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
	if err := applyConfigFlags(config,
		boolFlag(workflow.FlagAllProjects, &opts.Global.AllProjects),
		boolFlag(workflow.FlagUvWorkspacePackages, &opts.Global.ForceIncludeWorkspacePackages),
		boolFlag(workflow.FlagDev, &opts.Global.IncludeDev),
		boolFlag(workflow.FlagFailFast, &opts.Global.FailFast),
		boolFlag(workflow.FlagForceSingleGraph, &opts.Global.ForceSingleGraph),
		boolFlag(workflow.FlagIncludeProvenance, &opts.Global.IncludeProvenance),
		boolFlag(workflow.FlagNugetAssetsProjectName, &opts.Dotnet.AssetsProjectName),
		boolFlag(workflow.FlagAllSubProjects, &opts.Gradle.AllSubProjects),
		boolFlag(workflow.FlagGradleNormalizeDeps, &opts.Gradle.NormalizeDeps),
		stringFlag(workflow.FlagConfigurationMatching, &opts.Gradle.ConfigurationMatching),
		stringFlag(workflow.FlagConfigurationAttributes, &opts.Gradle.ConfigurationAttributes),
		stringFlag(workflow.FlagInitScript, &opts.Gradle.InitScript),
		stringFlag(workflow.FlagDotnetTargetFramework, &opts.Dotnet.TargetFramework),
		stringFlag(workflow.FlagNugetPkgsFolder, &opts.Dotnet.PackagesFolder),
		stringFlag(workflow.FlagGradleSubProject, &opts.Gradle.SubProject, workflow.FlagSubProject),
		parsedStringFlag(workflow.FlagStrictOutOfSync, &opts.Global.AllowOutOfSync, parseAllowOutOfSync),
		parsedStringFlag(workflow.FlagExclude, &opts.Global.Exclude, parseConfiguredExcludes),
		parsedStringFlag(workflow.FlagExcludePaths, &opts.Global.ExcludePaths, parseConfiguredExcludes),
		nonEmptyStringFlag(workflow.FlagFile, &opts.Global.TargetFile),
		parsedStringFlag(workflow.FlagDetectionDepth, &opts.Global.DetectionDepth, ParseDetectionDepth),
	); err != nil {
		return err
	}

	// The CLI resolves --packages-folder from the working directory.
	if packagesFolder := opts.Dotnet.PackagesFolder; packagesFolder != "" {
		if abs, err := filepath.Abs(packagesFolder); err == nil {
			opts.WithPackagesFolder(abs)
		}
	}
	return nil
}

func parseAllowOutOfSync(raw string) (bool, error) {
	strict, err := strconv.ParseBool(raw)
	return err == nil && !strict, nil
}

func parseConfiguredExcludes(raw string) (CommaSeparatedString, error) {
	return CommaSeparatedString(parseExcludeFlag(raw)), nil
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
