package depgraph

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	dg "github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/conversion"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/python/uv"
)

func Test_buildSCAPlugins_sharedNativeRegistry(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		want  []string
	}{
		{name: "flags disabled", want: []string{"uv", "legacycli"}},
		{name: "cargo enabled", flags: []string{orchestrator.FlagCargoResolver.Key}, want: []string{"cargo", "uv", "legacycli"}},
		{name: "all native scanners enabled", flags: []string{
			orchestrator.FlagBazelResolver.Key, orchestrator.FlagBunResolver.Key,
			orchestrator.FlagPnpmResolver.Key, orchestrator.FlagNewGradleResolver.Key,
			orchestrator.FlagCargoResolver.Key, orchestrator.FlagDotnetResolver.Key,
		}, want: []string{"bazel", "bun", "pnpm", "gradle", "cargo", "dotnet", "uv", "legacycli"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestContext(t, false)
			tc.config.Set(workflow.FlagUseSBOMResolution, true)
			for _, flag := range tt.flags {
				tc.config.Set(flag, true)
			}

			plugins, err := buildSCAPlugins(tc.invocationContext, nil)
			require.NoError(t, err)

			assert.Equal(t, tt.want, pluginNames(plugins))
		})
	}
}

// The converter and command outputs are fixtures; discovery, graph building,
// plugin ordering, result conversion and the legacy bridge run their real paths.
type registrySBOMConverter struct {
	graph *dg.DepGraph
	calls int
}

func (c *registrySBOMConverter) ConvertSBOM(context.Context, io.Reader, conversion.ConvertSBOMOptions) ([]*dg.DepGraph, []conversion.Warning, error) {
	c.calls++
	return []*dg.DepGraph{c.graph}, nil, nil
}

func Test_handleSBOMResolution_mixedCargoUVRegistry(t *testing.T) {
	cases := []struct {
		name         string
		cargoEnabled bool
		allProjects  bool
		wantTargets  []string
		wantExcluded []string
		cargoFails   bool
		failFast     bool
		wantUV       bool
		wantWarning  bool
		wantError    string
	}{
		{
			name: "all projects native cargo and uv", cargoEnabled: true, allProjects: true, wantUV: true,
			wantTargets:  []string{"Cargo.toml", "pyproject.toml", "package.json"},
			wantExcluded: []string{"Cargo.lock", "Cargo.toml", "uv.lock", "pyproject.toml", "requirements.txt"},
		},
		{
			name: "cargo flag disabled", allProjects: true, wantUV: true,
			wantTargets:  []string{"pyproject.toml", "package.json"},
			wantExcluded: []string{"uv.lock", "pyproject.toml", "requirements.txt"},
		},
		{
			name: "single project uses native precedence", cargoEnabled: true,
			wantTargets: []string{"Cargo.toml"},
		},
		{
			name: "cargo failure keeps other ecosystems in all projects", cargoEnabled: true, allProjects: true,
			cargoFails: true, wantUV: true, wantWarning: true,
			wantTargets:  []string{"pyproject.toml", "package.json"},
			wantExcluded: []string{"Cargo.lock", "Cargo.toml", "uv.lock", "pyproject.toml", "requirements.txt"},
		},
		{
			name: "single project surfaces cargo failure before uv", cargoEnabled: true,
			cargoFails: true, wantError: "cargo metadata failed",
		},
		{
			name: "fail fast aborts after cargo failure", cargoEnabled: true, allProjects: true,
			cargoFails: true, failFast: true, wantError: "Failed to scan Cargo.toml",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestContext(t, false)
			tc.config.Set(workflow.FlagUseSBOMResolution, true)
			if tt.wantWarning {
				tc.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...ui.Opts) error {
					assert.Contains(t, err.Error(), "Cargo.toml")
					assert.Contains(t, err.Error(), "1/3 potential projects failed")
					return nil
				})
			}
			harness := NewLegacyHarness(tc)
			harness.ReturnTargets = []string{"package.json"}
			root := t.TempDir()
			for _, path := range []string{"Cargo.lock", "Cargo.toml", "uv.lock", "pyproject.toml"} {
				path = filepath.Join(root, path)
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
				require.NoError(t, os.WriteFile(path, nil, 0o600))
			}
			binaries := t.TempDir()
			cargoDir := root
			metadata := fmt.Sprintf(`{
 "packages":[{"name":"rust-app","version":"0.1.0","id":"rust-app","manifest_path":%q}],
 "workspace_members":["rust-app"],"workspace_root":%q
}`, filepath.Join(cargoDir, "Cargo.toml"), cargoDir)
			cargoScript := fmt.Sprintf(`#!/bin/sh
case "$1" in
metadata) printf '%%s' '%s';;
tree) printf '0rust-app v0.1.0\n1serde v1.0.193\n';;
*) exit 1;;
esac
`, metadata)
			if tt.cargoFails {
				cargoScript = "#!/bin/sh\nprintf 'cargo metadata fixture failure' >&2\nexit 1\n"
			}
			uvScript := `#!/bin/sh
case "$1" in
--version) printf 'uv 0.9.29';;
export) printf '%s' '{"metadata":{"component":{"name":"python-app","version":"1.0.0","properties":[{"name":"uv:package:is_project_root","value":"true"}]}}}';;
*) exit 1;;
esac
`
			require.NoError(t, os.WriteFile(filepath.Join(binaries, "cargo"), []byte(cargoScript), 0o600))
			require.NoError(t, os.Chmod(filepath.Join(binaries, "cargo"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(binaries, "uv"), []byte(uvScript), 0o600))
			require.NoError(t, os.Chmod(filepath.Join(binaries, "uv"), 0o700))
			t.Setenv("PATH", binaries)
			tc.config.Set(configuration.INPUT_DIRECTORY, root)
			tc.config.Set(workflow.FlagAllProjects, tt.allProjects)
			tc.config.Set(workflow.FlagFailFast, tt.failFast)
			tc.config.Set(orchestrator.FlagCargoResolver.Key, tt.cargoEnabled)
			converter := registrySBOMConverter{graph: createTestDepGraph(t, "uv", "python-app", "1.0.0")}
			plugins, err := buildSCAPlugins(tc.invocationContext, &converter)
			require.NoError(t, err)

			data, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, plugins)

			assert.Equal(t, tt.wantUV, converter.calls > 0)
			assert.Equal(t, tt.allProjects && !tt.failFast, harness.Called())
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				assert.Empty(t, data)
				return
			}
			require.NoError(t, err)
			targets := make([]string, 0, len(data))
			for _, item := range data {
				targets = append(targets, metaString(t, item, workflow.MetaKeyNormalisedTargetFile))
			}
			assert.Equal(t, tt.wantTargets, targets)
			if tt.allProjects {
				assert.ElementsMatch(t, tt.wantExcluded, parseExcludeFlag(harness.CapturedExcludePaths()))
				assert.Empty(t, harness.CapturedExclude())
			}
		})
	}
}

// The SBOM flow shares native scanner gates and ordering with the orchestrator.
func buildSCAPlugins(
	ctx gafworkflow.InvocationContext,
	converter conversion.SBOMConverter,
) ([]ecosystems.SCAPlugin, error) {
	registry, err := orchestrator.NewPluginRegistry(ctx, orchestrator.WithUVPlugin(uv.NewPlugin(uv.NewClient(), converter, "")))
	if err != nil {
		return nil, fmt.Errorf("building scanner registry: %w", err)
	}
	return registry.Plugins(), nil
}
