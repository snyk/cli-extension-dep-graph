package depgraph

import (
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
)

func Test_buildPluginOptions_nativeFlags(t *testing.T) {
	maxTargets := 23
	for _, tt := range []struct {
		name           string
		raw            []string
		config         map[string]any
		wantGradle     ecosystems.GradleOptions
		wantBazel      ecosystems.BazelOptions
		wantProvenance bool
	}{
		{
			name: "raw native flags survive", raw: []string{
				"--gradle-sub-project=api", "--configuration-matching=runtime.*", "--configuration-attributes=usage:java-runtime",
				"--all-sub-projects", "--init-script=custom.gradle", "--gradle-skip-wrapper", "--gradle-normalize-deps",
				"--include-provenance", "--bazel-jvm", "--bazel-go", "--bazel-platforms=//platform:linux",
				"--bazel-target-query=kind(go_library, //...)", "--bazel-max-targets=23",
			},
			wantGradle: ecosystems.GradleOptions{
				SubProject: "api", ConfigurationMatching: "runtime.*",
				ConfigurationAttributes: "usage:java-runtime", AllSubProjects: true,
				InitScript: "custom.gradle", SkipWrapper: true, NormalizeDeps: true,
			},
			wantBazel: ecosystems.BazelOptions{
				TargetQuery: "kind(go_library, //...)", MaxTargets: &maxTargets, Jvm: true, Go: true, Platforms: "//platform:linux",
			},
			wantProvenance: true,
		},
		{
			name: "config selectors override raw", raw: []string{"--gradle-sub-project=raw", "--include-provenance"},
			config: map[string]any{
				workflow.FlagGradleSubProject: "configured", workflow.FlagConfigurationMatching: "compile.*",
				workflow.FlagConfigurationAttributes: "usage:java-api", workflow.FlagAllSubProjects: true, workflow.FlagInitScript: "init.gradle",
				workflow.FlagGradleNormalizeDeps: true, workflow.FlagIncludeProvenance: false,
			},
			wantGradle: ecosystems.GradleOptions{
				SubProject: "configured", ConfigurationMatching: "compile.*",
				ConfigurationAttributes: "usage:java-api", AllSubProjects: true,
				InitScript: "init.gradle", NormalizeDeps: true,
			},
		},
		{
			name: "config canonical selector takes precedence", raw: []string{"--sub-project=raw"},
			config:     map[string]any{workflow.FlagGradleSubProject: "canonical", workflow.FlagSubProject: "alias"},
			wantGradle: ecosystems.GradleOptions{SubProject: "canonical"},
		},
		{name: "raw sub-project alias", raw: []string{"--sub-project=alias"}, wantGradle: ecosystems.GradleOptions{SubProject: "alias"}},
		{name: "config sub-project alias", config: map[string]any{workflow.FlagSubProject: "alias"}, wantGradle: ecosystems.GradleOptions{SubProject: "alias"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			cfg.Set(orchestrator.FlagNewGradleResolver.Key, true)
			cfg.Set(orchestrator.FlagBazelResolver.Key, true)
			cfg.Set(configuration.RAW_CMD_ARGS, tt.raw)
			for key, value := range tt.config {
				cfg.Set(key, value)
			}

			opts, err := buildPluginOptions(cfg)

			require.NoError(t, err)
			assert.Equal(t, tt.wantGradle, opts.Gradle)
			assert.Equal(t, tt.wantBazel, opts.Bazel)
			assert.Equal(t, tt.wantProvenance, opts.Global.IncludeProvenance)
		})
	}
}

func Test_buildPluginOptions_configuredScope(t *testing.T) {
	for _, tt := range []struct {
		name           string
		disabledNative bool
		raw            []string
		config         map[string]any
		want           ecosystems.GlobalOptions
		wantDotnet     ecosystems.DotnetOptions
	}{
		{name: "malformed unrelated raw depth ignored", raw: []string{"--detection-depth=invalid"}},
		{name: "missing unrelated raw value ignored", raw: []string{"--project-name"}},
		{name: "raw workspace selector does not activate UV selection", raw: []string{"--workspace-package=api"}},
		{name: "unrelated raw options preserve defaults", raw: []string{
			"--all-projects", "--internal-uv-workspace-packages", "--dev", "--strict-out-of-sync=false",
			"--exclude=raw", "--exclude-paths=raw", "--fail-fast", "--force-single-graph", "--file=raw",
			"--project-name=raw", "--no-build-isolation", "--assets-project-name", "--packages-folder=raw", "--dotnet-target-framework=raw",
		}},
		{name: "disabled native malformed values ignored", disabledNative: true, raw: []string{"--bazel-max-targets=invalid", "--configuration-matching"}},
		{
			name: "config wins over unrelated malformed raw flags", raw: []string{"--detection-depth=invalid", "--file=raw", "--exclude=raw"},
			config: map[string]any{
				workflow.FlagAllProjects: true, workflow.FlagUvWorkspacePackages: true, workflow.FlagDev: true,
				workflow.FlagStrictOutOfSync: "false", workflow.FlagExclude: " one, , two ", workflow.FlagExcludePaths: " path, , other ",
				workflow.FlagFailFast: true, workflow.FlagForceSingleGraph: true, workflow.FlagFile: "configured",
				workflow.FlagDetectionDepth: "3", workflow.FlagNugetAssetsProjectName: true,
				workflow.FlagNugetPkgsFolder: "/configured/packages", workflow.FlagDotnetTargetFramework: "net8.0",
			},
			want: ecosystems.GlobalOptions{
				AllProjects: true, ForceIncludeWorkspacePackages: true, IncludeDev: true, AllowOutOfSync: true,
				Exclude: ecosystems.CommaSeparatedString{"one", "two"}, ExcludePaths: ecosystems.CommaSeparatedString{"path", "other"},
				FailFast: true, ForceSingleGraph: true, TargetFile: stringPtr("configured"), DetectionDepth: 3,
			},
			wantDotnet: ecosystems.DotnetOptions{AssetsProjectName: true, PackagesFolder: filepath.FromSlash("/configured/packages"), TargetFramework: "net8.0"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			cfg.Set(orchestrator.FlagNewGradleResolver.Key, !tt.disabledNative)
			cfg.Set(orchestrator.FlagBazelResolver.Key, !tt.disabledNative)
			cfg.Set(configuration.RAW_CMD_ARGS, tt.raw)
			for key, value := range tt.config {
				cfg.Set(key, value)
			}

			opts, err := buildPluginOptions(cfg)

			require.NoError(t, err)
			assert.Equal(t, tt.want, opts.Global)
			assert.Equal(t, ecosystems.PythonOptions{}, opts.Python)
			wantDotnet := tt.wantDotnet
			wantDotnet.CLIProjectIdentity = true
			assert.Equal(t, wantDotnet, opts.Dotnet)
		})
	}
}
