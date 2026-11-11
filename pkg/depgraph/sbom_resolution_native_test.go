package depgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
)

func Test_handleSBOMResolution_nativeFirst(t *testing.T) {
	for _, tt := range []struct {
		name                                                  string
		cargoEnabled, dotnetEnabled, allProjects, emptyNative bool
		wantTargets                                           []string
		wantUV, wantLegacy                                    bool
		cargoError, failFast, wantError, wantWarning          bool
	}{
		{
			name: "mixed projects", cargoEnabled: true, dotnetEnabled: true, allProjects: true,
			wantTargets: []string{"Cargo.toml", "obj/project.assets.json", "uv.lock", "package.json"}, wantUV: true, wantLegacy: true,
		},
		{name: "default cargo precedence", cargoEnabled: true, dotnetEnabled: true, wantTargets: []string{"Cargo.toml"}},
		{name: "cargo disabled retains nuget gate", dotnetEnabled: true, wantTargets: []string{"obj/project.assets.json"}},
		{name: "flags off", allProjects: true, wantTargets: []string{"uv.lock", "package.json"}, wantUV: true, wantLegacy: true},
		{
			name: "empty native falls through", cargoEnabled: true, dotnetEnabled: true, allProjects: true, emptyNative: true,
			wantTargets: []string{"uv.lock", "package.json"}, wantUV: true, wantLegacy: true,
		},
		{
			name: "cargo failure keeps remaining projects", cargoEnabled: true, cargoError: true, allProjects: true,
			wantTargets: []string{"uv.lock", "package.json"}, wantUV: true, wantLegacy: true, wantWarning: true,
		},
		{name: "default cargo failure returns error", cargoEnabled: true, cargoError: true, wantError: true},
		{name: "fail fast stops after cargo failure", cargoEnabled: true, dotnetEnabled: true, cargoError: true, allProjects: true, failFast: true, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestContext(t, false)
			if tt.wantWarning {
				tc.userInterface.EXPECT().OutputError(gomock.Any()).Return(nil).Times(1)
			}
			dir := t.TempDir()
			if !tt.emptyNative {
				dir = sdkStyleProject(t)
				require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[package]\nname = 'app'\nversion = '1.0.0'\n"), 0o600))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte("version = 3\n"), 0o600))
			}
			fakeCargoBinary(t, dir, tt.cargoError)
			tc.config.Set(configuration.INPUT_DIRECTORY, dir)
			tc.config.Set(workflow.FlagAllProjects, tt.allProjects)
			tc.config.Set(workflow.FlagFailFast, tt.failFast)
			tc.config.Set(orchestrator.FlagCargoResolver.Key, tt.cargoEnabled)
			tc.config.Set(orchestrator.FlagDotnetResolver.Key, tt.dotnetEnabled)
			plugins, err := buildSCAPlugins(tc.invocationContext, tc.config, nil, "")
			require.NoError(t, err)
			uvPlugin := &mockScaPlugin{name: "uv", results: []ecosystems.SCAResult{withProcessedFiles(ecosystems.SCAResult{
				DepGraph:         createTestDepGraph(t, "uv", "python-app", "1.0.0"),
				ResolverMetadata: &ecosystems.ResolverMetadata{NormalisedTargetFile: "uv.lock"},
			}, "uv.lock")}}
			legacyPlugin := &mockScaPlugin{name: "legacycli", results: []ecosystems.SCAResult{{
				DepGraph:         createTestDepGraph(t, "npm", "node-app", "1.0.0"),
				ResolverMetadata: &ecosystems.ResolverMetadata{NormalisedTargetFile: "package.json"},
			}}}
			plugins[1], plugins[2] = uvPlugin, legacyPlugin

			data, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, plugins)

			assert.Equal(t, tt.wantUV, uvPlugin.options != nil)
			assert.Equal(t, tt.wantLegacy, legacyPlugin.options != nil)
			if tt.wantError {
				require.Error(t, err)
				assert.Nil(t, data)
				return
			}
			require.NoError(t, err)
			targets := make([]string, len(data))
			for i, item := range data {
				targets[i] = metaString(t, item, workflow.MetaKeyNormalisedTargetFile)
			}
			assert.Equal(t, tt.wantTargets, targets)
			if tt.wantLegacy {
				excluded := []string(legacyPlugin.options.Global.ExcludePaths)
				assert.Contains(t, excluded, "uv.lock")
				if tt.cargoEnabled && !tt.emptyNative {
					assert.Contains(t, excluded, "Cargo.lock")
					assert.Contains(t, excluded, "Cargo.toml")
					if tt.dotnetEnabled {
						assert.Contains(t, excluded, "obj/project.assets.json")
					}
				}
			}
		})
	}
}

// Only cargo's subprocess output is stubbed; discovery, gates and graph building run.
func fakeCargoBinary(t *testing.T, dir string, fail bool) {
	t.Helper()
	binaryDir := t.TempDir()
	metadata := fmt.Sprintf(`{"packages":[{"name":"app","version":"1.0.0","id":"app","manifest_path":%q}],"workspace_members":["app"],"workspace_root":%q}`,
		filepath.Join(dir, "Cargo.toml"), dir)
	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\nmetadata) cat <<'CARGO_METADATA'\n%s\nCARGO_METADATA\n;;\n"+
		"tree) printf '0app v1.0.0\\n' ;;\nesac\n", metadata)
	if fail {
		script = "#!/bin/sh\necho cargo fixture failed >&2\nexit 1\n"
	}
	binaryPath := filepath.Join(binaryDir, "cargo")
	require.NoError(t, os.WriteFile(binaryPath, []byte(script), 0o600))
	require.NoError(t, os.Chmod(binaryPath, 0o700))
	t.Setenv("PATH", binaryDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
