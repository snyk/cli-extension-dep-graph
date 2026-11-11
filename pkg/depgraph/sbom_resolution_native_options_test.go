package depgraph

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/bazel"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

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
			opts, err := ecosystems.NewPluginOptionsFromConfig(cfg)
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
