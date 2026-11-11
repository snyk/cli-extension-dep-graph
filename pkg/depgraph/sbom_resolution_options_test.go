package depgraph

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

func Test_buildPluginOptions_nativeFlags(t *testing.T) {
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
			},
			wantGradle: ecosystems.GradleOptions{
				SubProject: "api", ConfigurationMatching: "runtime.*",
				ConfigurationAttributes: "usage:java-runtime", AllSubProjects: true,
				InitScript: "custom.gradle", SkipWrapper: true, NormalizeDeps: true,
			},
			wantBazel: ecosystems.BazelOptions{Jvm: true, Go: true, Platforms: "//platform:linux"}, wantProvenance: true,
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
		{name: "config sub-project alias", config: map[string]any{workflow.FlagSubProject: "alias"}, wantGradle: ecosystems.GradleOptions{SubProject: "alias"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			cfg.Set(configuration.RAW_CMD_ARGS, tt.raw)
			for key, value := range tt.config {
				cfg.Set(key, value)
			}

			opts, err := buildPluginOptions(cfg)

			require.NoError(t, err)
			assert.Equal(t, tt.wantGradle, opts.Gradle)
			assert.Equal(t, tt.wantBazel, opts.Bazel)
			assert.Equal(t, tt.wantProvenance, opts.Global.IncludeProvenance)
			assert.Equal(t, tt.raw, opts.Global.RawFlags)
		})
	}
}
