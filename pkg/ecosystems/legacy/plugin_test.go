//nolint:lll // Large JSON fixtures inlined in this file.
package legacy_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	gafworkflow "github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "legacycli", legacy.NewPlugin(nil).GetName())
}

func TestPlugin_MapsProjectType(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","targetFileFromPlugin":"package.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, results.Results, 1)
	assert.Equal(t, "npm", results.Results[0].ProjectDescriptor.Identity.ProjectType)
}

func TestPlugin_MapsTargetFramework(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json","target":{},"targetRuntime":"net6.0"}`, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, results.Results, 1)
	assert.Equal(t, "net6.0", *results.Results[0].ProjectDescriptor.Identity.TargetRuntime)
}

// TestPlugin_TargetFileFromTable verifies the dual-field semantic for legacy CLI results:
//   - Identity.TargetFile is always populated with the parsed file path so downstream
//     consumers can identify which manifest a result came from.
//   - Identity.Legacy.SuppressTargetFileFromPlugin mirrors the legacy CLI's
//     `targetFileFromPlugin` presence-vs-absence semantic via shouldSuppressTargetFileFromPlugin —
//     true for project types whose snyk plugin does NOT set plugin.targetFile, false otherwise.
//     ProjectDescriptor.GetTargetFileForPlugin() exposes this as the public contract.
func TestPlugin_TargetFileFromTable(t *testing.T) {
	cases := map[string]struct {
		body                   string
		wantTargetFile         string // expected Identity.TargetFile (always set)
		wantSuppressFromPlugin bool   // expected Identity.Legacy.SuppressTargetFileFromPlugin
	}{
		// Plugin sets plugin.targetFile to the input file (suppress = false):
		"pip Pipfile": {
			body:                   `{"depGraph":{"pkgManager":{"name":"pip"}},"normalisedTargetFile":"Pipfile"}`,
			wantTargetFile:         "Pipfile",
			wantSuppressFromPlugin: false,
		},
		"gradle.kts": {
			body:                   `{"depGraph":{"pkgManager":{"name":"gradle"}},"normalisedTargetFile":"build.gradle.kts"}`,
			wantTargetFile:         "build.gradle.kts",
			wantSuppressFromPlugin: false,
		},
		"poetry": {
			body:                   `{"depGraph":{"pkgManager":{"name":"poetry"}},"normalisedTargetFile":"poetry.lock"}`,
			wantTargetFile:         "poetry.lock",
			wantSuppressFromPlugin: false,
		},
		"nuget": {
			body:                   `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json"}`,
			wantTargetFile:         "project.assets.json",
			wantSuppressFromPlugin: false,
		},
		// Plugin does not set plugin.targetFile (suppress = true), but
		// Identity.TargetFile is still populated with the manifest path:
		"maven": {
			body:                   `{"depGraph":{"pkgManager":{"name":"maven"}},"normalisedTargetFile":"pom.xml"}`,
			wantTargetFile:         "pom.xml",
			wantSuppressFromPlugin: true,
		},
		"sbt": {
			body:                   `{"depGraph":{"pkgManager":{"name":"sbt"}},"normalisedTargetFile":"build.sbt"}`,
			wantTargetFile:         "build.sbt",
			wantSuppressFromPlugin: true,
		},
		"rubygems": {
			body:                   `{"depGraph":{"pkgManager":{"name":"rubygems"}},"normalisedTargetFile":"Gemfile.lock"}`,
			wantTargetFile:         "Gemfile.lock",
			wantSuppressFromPlugin: true,
		},
		"pip requirements.txt": {
			body:                   `{"depGraph":{"pkgManager":{"name":"pip"}},"normalisedTargetFile":"requirements.txt"}`,
			wantTargetFile:         "requirements.txt",
			wantSuppressFromPlugin: true,
		},
		"npm non-workspace": {
			body:                   `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package-lock.json"}`,
			wantTargetFile:         "package-lock.json",
			wantSuppressFromPlugin: true,
		},
		"npm workspace": {
			body:                   `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package-lock.json","workspace":{}}`,
			wantTargetFile:         "package-lock.json",
			wantSuppressFromPlugin: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ictx, _ := setupLegacyCLI(t, tc.body, nil)
			plugin := legacy.NewPlugin(ictx)

			res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
			require.NoError(t, err)
			require.Len(t, res.Results, 1)

			pd := res.Results[0].ProjectDescriptor
			require.NotNil(t, pd.Identity.TargetFile, "Identity.TargetFile must always be populated")
			assert.Equal(t, tc.wantTargetFile, *pd.Identity.TargetFile)

			require.NotNil(t, pd.Identity.Legacy, "legacy plugin should always populate Identity.Legacy")
			assert.Equal(t, tc.wantSuppressFromPlugin, pd.Identity.Legacy.SuppressTargetFileFromPlugin,
				"SuppressTargetFileFromPlugin should match the plugin-targetFile table")

			pluginTF := pd.GetTargetFileForPlugin()
			if tc.wantSuppressFromPlugin {
				assert.Nil(t, pluginTF, "GetTargetFileForPlugin should return nil when suppression is on")
			} else {
				require.NotNil(t, pluginTF, "GetTargetFileForPlugin should return Identity.TargetFile when suppression is off")
				assert.Equal(t, tc.wantTargetFile, *pluginTF)
			}
		})
	}
}

func TestPlugin_ForwardsTargetFromUpstream(t *testing.T) {
	t.Run("forwards target bytes when the legacy CLI provides them", func(t *testing.T) {
		body := `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{"remoteUrl":"https://example.com/repo"}}`
		ictx, _ := setupLegacyCLI(t, body, nil)
		plugin := legacy.NewPlugin(ictx)

		res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
		require.NoError(t, err)
		require.Len(t, res.Results, 1)

		require.NotNil(t, res.Results[0].ProjectDescriptor.Identity.Legacy)
		assert.Equal(t, `{"remoteUrl":"https://example.com/repo"}`, string(res.Results[0].ProjectDescriptor.Identity.Legacy.Target),
			"target should be forwarded as raw bytes for downstream Snyk CLI consumers")
	})

	t.Run("leaves Identity.Legacy.Target nil when the legacy CLI does not emit it", func(t *testing.T) {
		body := `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json"}`
		ictx, _ := setupLegacyCLI(t, body, nil)
		plugin := legacy.NewPlugin(ictx)

		res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
		require.NoError(t, err)
		require.Len(t, res.Results, 1)

		legacy := res.Results[0].ProjectDescriptor.Identity.Legacy
		if legacy != nil {
			assert.Nil(t, legacy.Target)
		}
	})
}

func TestPlugin_MapsRootComponentName(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"nuget"},"pkgs":[{"id":"my-project@","info":{"name":"my-project"}}],"graph":{"rootNodeId":"root","nodes":[{"nodeId":"root","pkgId":"my-project@"}]}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, res.Results, 1)
	assert.Equal(t, "my-project", res.Results[0].ProjectDescriptor.Identity.RootComponentName)
}

func TestPlugin_PopulatesResolverMetadata(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, res.Results, 1)
	require.NotNil(t, res.Results[0].ResolverMetadata)
	assert.Equal(t, "legacycli", res.Results[0].ResolverMetadata.PluginName)
}

func TestPlugin_ReturnsProcessedFiles(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json","target":{}}`, nil)

	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	assert.Equal(t, []string{"project.assets.json"}, res.ProcessedFiles)
}

func TestPlugin_PerResultErrorPopulatesSCAResultError(t *testing.T) {
	body := `{"normalisedTargetFile":"broken/pom.xml","error":{"jsonapi":{"version":"1.0"},"errors":[{"id":"abc","status":"500","code":"SNYK-LEGACY-MOD-001","title":"Module failed","detail":"Could not resolve","meta":{"isErrorCatalogError":true,"classification":"ACTIONABLE"}}]}}`
	ictx, _ := setupLegacyCLI(t, body, nil)
	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, res.Results, 1)

	require.Error(t, res.Results[0].Error)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(res.Results[0].Error, &snykErr))
	assert.Equal(t, "SNYK-LEGACY-MOD-001", snykErr.ErrorCode)
	assert.Equal(t, "Module failed", snykErr.Title)
}

func TestPlugin_PerResultCLIErrorIsPreservedWhenDepGraphIsMalformed(t *testing.T) {
	// Output carries both an upstream CLI error AND a malformed depgraph payload. The
	// CLI error is the user-meaningful one, so the unmarshal failure must not overwrite it.
	body := `{"normalisedTargetFile":"broken/pom.xml","depGraph":"not-valid-json","error":{"jsonapi":{"version":"1.0"},"errors":[{"id":"abc","status":"500","code":"SNYK-LEGACY-MOD-002","title":"Upstream failure","detail":"Module fetch failed","meta":{"isErrorCatalogError":true,"classification":"ACTIONABLE"}}]}}`
	ictx, _ := setupLegacyCLI(t, body, nil)
	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, res.Results, 1)

	require.Error(t, res.Results[0].Error)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(res.Results[0].Error, &snykErr), "upstream CLI error should be preserved, not overwritten by depgraph unmarshal failure")
	assert.Equal(t, "SNYK-LEGACY-MOD-002", snykErr.ErrorCode)
}

func TestPlugin_ExitCode3ReturnsEmptySuccess(t *testing.T) {
	ictx := setupLegacyCLIWithError(t, exitCodeError{code: 3})
	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.Results)
	assert.Empty(t, res.ProcessedFiles)
}

func TestPlugin_ErrNoDepGraphsFoundReturnsEmptySuccess(t *testing.T) {
	ictx := setupLegacyCLIWithEmptyData(t)
	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Empty(t, res.Results)
}

func TestPlugin_NonExitCode3ErrorIsWrapped(t *testing.T) {
	underlying := fmt.Errorf("network unreachable")
	ictx := setupLegacyCLIWithError(t, underlying)
	plugin := legacy.NewPlugin(ictx)

	res, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error handling legacy workflow")
	assert.ErrorIs(t, err, underlying, "underlying error should remain in the chain via the snyk_errors.WithCause wrap")
	assert.Nil(t, res)
}

func TestPlugin_NilOptionsReturnsError(t *testing.T) {
	plugin := legacy.NewPlugin(nil)

	_, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "options")
}

func TestPlugin_ExcludeBehaviour(t *testing.T) {
	// `opts.Global.Exclude` is intentionally not merged into the legacy CLI's `--exclude` flag.
	// The legacy CLI's `--exclude` only matches basenames and folder names, which is unsafe for
	// workspace-style projects where multiple packages share the same manifest filename. ProcessedFiles
	// propagation to the legacy CLI will be wired up via `--exclude-paths` once snyk/cli#6741
	// and snyk/cli-extension-dep-graph#152 land. Until then, the contract is:
	//   - The user-supplied `--exclude` (already on the live config) is preserved unchanged.
	//   - `opts.Global.Exclude` is ignored by the legacy plugin.

	t.Run("opts.Exclude is NOT forwarded to the legacy config", func(t *testing.T) {
		ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, nil)
		plugin := legacy.NewPlugin(ictx)

		opts := ecosystems.NewPluginOptions().WithExclude([]string{"a.lock", "b.lock"})
		_, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", opts)
		require.NoError(t, err)

		assert.Equal(t, "", (*capturedConfig).GetString(workflow.FlagExclude),
			"opts.Exclude must not leak into the legacy CLI --exclude until --exclude-paths support lands")
	})

	t.Run("user-supplied FlagExclude on the live config is preserved on the clone", func(t *testing.T) {
		preexisting := map[string]any{workflow.FlagExclude: "user-exclude.txt"}
		ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, preexisting)
		plugin := legacy.NewPlugin(ictx)

		opts := ecosystems.NewPluginOptions().WithExclude([]string{"a.lock"})
		_, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", opts)
		require.NoError(t, err)

		assert.Equal(t, "user-exclude.txt", (*capturedConfig).GetString(workflow.FlagExclude),
			"the user's --exclude flows through unmodified; opts.Exclude is ignored")
	})
}

func TestPlugin_DoesNotMutateLiveConfig(t *testing.T) {
	preexisting := map[string]any{workflow.FlagExclude: "user-exclude.txt"}
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, preexisting)
	plugin := legacy.NewPlugin(ictx)

	opts := ecosystems.NewPluginOptions().WithExclude([]string{"a.lock"})
	_, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", opts)
	require.NoError(t, err)

	assert.Equal(t, "user-exclude.txt", ictx.GetConfiguration().GetString(workflow.FlagExclude),
		"live config exclude should not be mutated; merge happens on a clone")
}

func TestPlugin_ForcesEffectiveGraphWithErrorsByDefault(t *testing.T) {
	ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	_, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	assert.True(t, (*capturedConfig).GetBool(workflow.FlagPrintEffectiveGraphWithErrors))
}

func TestPlugin_DisablesEffectiveGraphWithErrorsWhenJSONLWithErrorsRequested(t *testing.T) {
	preexisting := map[string]any{workflow.FlagPrintOutputJsonlWithErrors: true}
	ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, preexisting)
	plugin := legacy.NewPlugin(ictx)

	_, err := plugin.BuildDepGraphsFromDir(t.Context(), logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	assert.False(t, (*capturedConfig).GetBool(workflow.FlagPrintEffectiveGraphWithErrors))
	assert.True(t, (*capturedConfig).GetBool(workflow.FlagPrintOutputJsonlWithErrors))
}

// setupLegacyCLI configures a mock InvocationContext whose engine returns the supplied JSONL body
// as the legacy CLI's payload. preexistingConfig keys are set on the live config before the plugin
// runs. The returned configuration pointer captures the cloned config the plugin passed to
// InvokeWithConfig, so tests can assert on what the plugin produced.
func setupLegacyCLI(t *testing.T, testBody string, preexistingConfig map[string]any) (gafworkflow.InvocationContext, *configuration.Configuration) {
	t.Helper()

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	engine := gafmocks.NewMockEngine(ctrl)
	cfg := configuration.New()
	for k, v := range preexistingConfig {
		cfg.Set(k, v)
	}
	logger := zerolog.Nop()

	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	var captured configuration.Configuration
	engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ gafworkflow.Identifier, c configuration.Configuration) ([]gafworkflow.Data, error) {
			captured = c
			return []gafworkflow.Data{
				gafworkflow.NewData(
					gafworkflow.NewTypeIdentifier(
						gafworkflow.NewWorkflowIdentifier("legacycli"),
						"application/text"),
					"application/text",
					[]byte(testBody)),
			}, nil
		})

	return ictx, &captured
}

func setupLegacyCLIWithError(t *testing.T, returnedErr error) gafworkflow.InvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	engine := gafmocks.NewMockEngine(ctrl)
	cfg := configuration.New()
	logger := zerolog.Nop()

	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return(nil, returnedErr)

	return ictx
}

func setupLegacyCLIWithEmptyData(t *testing.T) gafworkflow.InvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	engine := gafmocks.NewMockEngine(ctrl)
	cfg := configuration.New()
	logger := zerolog.Nop()

	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return([]gafworkflow.Data{}, nil)

	return ictx
}

// Ensure ErrNoDepGraphsFound stays observable from tests (compile-time pin).
var _ = legacycli.ErrNoDepGraphsFound

// exitCodeError is a minimal error type implementing legacycli.ExitCoder for tests.
type exitCodeError struct {
	code int
}

func (e exitCodeError) Error() string { return fmt.Sprintf("exit %d", e.code) }
func (e exitCodeError) ExitCode() int { return e.code }
