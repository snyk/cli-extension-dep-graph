package depgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/bazel"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

func Test_buildPluginOptions_nativeSelectors(t *testing.T) {
	cases := []struct {
		name       string
		raw        []string
		configured bool
		want       ecosystems.GradleOptions
	}{
		{name: "raw selectors survive absent config", raw: []string{
			"--configuration-matching=runtime.*", "--configuration-attributes=usage:java-runtime", "--sub-project=api",
			"--all-sub-projects", "--init-script=custom.gradle", "--gradle-skip-wrapper", "--gradle-normalize-deps",
			"--include-provenance", "--workspace-package=python-api", "--project-name=my-project", "--no-build-isolation",
		}, want: ecosystems.GradleOptions{
			ConfigurationMatching: "runtime.*", ConfigurationAttributes: "usage:java-runtime",
			SubProject: "api", AllSubProjects: true, InitScript: "custom.gradle", SkipWrapper: true, NormalizeDeps: true,
		}},
		{name: "config selectors override raw", configured: true, raw: []string{
			"--configuration-matching=raw", "--configuration-attributes=raw:value", "--gradle-sub-project=raw",
			"--all-sub-projects", "--init-script=raw.gradle", "--gradle-normalize-deps", "--include-provenance",
		}, want: ecosystems.GradleOptions{
			ConfigurationMatching: "compile.*", ConfigurationAttributes: "usage:java-api",
			SubProject: "service", InitScript: "configured.gradle",
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := configuration.New()
			cfg.Set(configuration.RAW_CMD_ARGS, tt.raw)
			if tt.configured {
				cfg.Set(workflow.FlagConfigurationMatching, "compile.*")
				cfg.Set(workflow.FlagConfigurationAttributes, "usage:java-api")
				cfg.Set(workflow.FlagGradleSubProject, "service")
				cfg.Set(workflow.FlagAllSubProjects, false)
				cfg.Set(workflow.FlagInitScript, "configured.gradle")
				cfg.Set(workflow.FlagGradleNormalizeDeps, false)
				cfg.Set(workflow.FlagIncludeProvenance, false)
			}

			opts, err := buildPluginOptions(cfg)

			require.NoError(t, err)
			assert.Equal(t, tt.want, opts.Gradle)
			assert.Equal(t, tt.raw, opts.Global.RawFlags)
			assert.Equal(t, !tt.configured, opts.Global.IncludeProvenance)
			if !tt.configured {
				require.NotNil(t, opts.Global.WorkspacePackage)
				assert.Equal(t, "python-api", *opts.Global.WorkspacePackage)
				require.NotNil(t, opts.Global.ProjectName)
				assert.Equal(t, "my-project", *opts.Global.ProjectName)
				assert.True(t, opts.Python.NoBuildIsolation)
			}
		})
	}
}

func Test_buildPluginOptions_activatesBazel(t *testing.T) {
	for _, flag := range []string{"--bazel-go", "--bazel-jvm"} {
		t.Run(flag, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n\ngo 1.24\n"), 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "maven_install.json"), []byte(`{"artifacts":{}}`), 0o600))
			marker := filepath.Join(dir, "queried")
			binaries := t.TempDir()
			script := "#!/bin/sh\nprintf '%s' \"$*\" > '" + marker + "'\n"
			require.NoError(t, os.WriteFile(filepath.Join(binaries, "bazel"), []byte(script), 0o600))
			require.NoError(t, os.Chmod(filepath.Join(binaries, "bazel"), 0o700))
			t.Setenv("PATH", binaries)
			cfg := configuration.New()
			raw := []string{flag, "--bazel-target-query=//app:all", "--bazel-platforms=//platform:linux", "--bazel-max-targets=20"}
			cfg.Set(configuration.RAW_CMD_ARGS, raw)
			opts, err := buildPluginOptions(cfg)
			require.NoError(t, err)

			err = (bazel.Plugin{}).BuildDepGraphsFromDir(context.Background(), logger.Nop(), dir, opts, func(ecosystems.SCAResult) error { return nil })

			require.NoError(t, err)
			queried, err := os.ReadFile(marker)
			require.NoError(t, err, "raw Bazel flag must activate its resolver")
			assert.Contains(t, string(queried), "//app:all")
			assert.Equal(t, "//platform:linux", opts.Bazel.Platforms)
			require.NotNil(t, opts.Bazel.MaxTargets)
			assert.Equal(t, 20, *opts.Bazel.MaxTargets)
		})
	}
}
