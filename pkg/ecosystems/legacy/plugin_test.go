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

	"github.com/snyk/cli-extension-dep-graph/v2/internal/legacycli"
	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "legacycli", legacy.NewPlugin(nil).GetName())
}

func TestPlugin_MapsProjectType(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","targetFileFromPlugin":"package.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "npm", results[0].ProjectDescriptor.Identity.ProjectType)
}

func TestPlugin_MapsTargetFramework(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json","target":{},"targetRuntime":"net6.0"}`, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "net6.0", *results[0].ProjectDescriptor.Identity.TargetRuntime)
}

// TestPlugin_TargetFileForwarding verifies the plugin forwards the legacy CLI's
// `targetFileFromPlugin` field verbatim onto Identity.TargetFile, and its
// `normalisedTargetFile` onto ResolverMetadata.NormalisedTargetFile. Downstream
// emission of MetaKeyTargetFileFromPlugin depends on Identity.TargetFile's nilness
// exactly matching the CLI's own.
func TestPlugin_TargetFileForwarding(t *testing.T) {
	cases := map[string]struct {
		body                 string
		wantNormalisedTarget string  // expected ResolverMetadata.NormalisedTargetFile
		wantPluginTargetFile *string // expected Identity.TargetFile
	}{
		"CLI emits targetFileFromPlugin → forwarded verbatim": {
			body:                 `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json"}`,
			wantNormalisedTarget: "project.assets.json",
			wantPluginTargetFile: stringPtr("project.assets.json"),
		},
		"CLI emits a distinct targetFileFromPlugin → forwarded verbatim": {
			body:                 `{"depGraph":{"pkgManager":{"name":"gradle"}},"normalisedTargetFile":"build.gradle.kts","targetFileFromPlugin":"something-else.kts"}`,
			wantNormalisedTarget: "build.gradle.kts",
			wantPluginTargetFile: stringPtr("something-else.kts"),
		},
		"CLI omits targetFileFromPlugin → forwarded as nil": {
			body:                 `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package-lock.json"}`,
			wantNormalisedTarget: "package-lock.json",
			wantPluginTargetFile: nil,
		},
		"CLI omits targetFileFromPlugin even when workspace is set": {
			body:                 `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package-lock.json","workspace":{"type":"npm"}}`,
			wantNormalisedTarget: "package-lock.json",
			wantPluginTargetFile: nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ictx, _ := setupLegacyCLI(t, tc.body, nil)
			plugin := legacy.NewPlugin(ictx)

			results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
			require.NoError(t, err)
			require.Len(t, results, 1)

			require.NotNil(t, results[0].ResolverMetadata, "legacy plugin must always populate ResolverMetadata")
			assert.Equal(t, tc.wantNormalisedTarget, results[0].ResolverMetadata.NormalisedTargetFile,
				"ResolverMetadata.NormalisedTargetFile must mirror the legacy CLI's normalisedTargetFile verbatim")

			if tc.wantPluginTargetFile == nil {
				assert.Nil(t, results[0].ProjectDescriptor.Identity.TargetFile,
					"Identity.TargetFile must be nil when the legacy CLI omitted targetFileFromPlugin")
			} else {
				require.NotNil(t, results[0].ProjectDescriptor.Identity.TargetFile)
				assert.Equal(t, *tc.wantPluginTargetFile, *results[0].ProjectDescriptor.Identity.TargetFile)
			}
		})
	}
}

func stringPtr(s string) *string { return &s }

func TestPlugin_MapsRootComponentName(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"nuget"},"pkgs":[{"id":"my-project@","info":{"name":"my-project"}}],"graph":{"rootNodeId":"root","nodes":[{"nodeId":"root","pkgId":"my-project@"}]}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, "my-project", results[0].ProjectDescriptor.Identity.RootComponentName)
}

func TestPlugin_PopulatesResolverMetadata(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, results, 1)
	require.NotNil(t, results[0].ResolverMetadata)
	assert.Equal(t, "legacycli", results[0].ResolverMetadata.PluginName)
}

func TestPlugin_ReturnsProcessedFiles(t *testing.T) {
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json","target":{}}`, nil)

	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	require.Len(t, results, 1)
	assert.Equal(t, []string{"project.assets.json"}, results[0].ProcessedFiles,
		"each result carries the lockfile it was derived from")
}

func TestPlugin_PerResultErrorPopulatesSCAResultError(t *testing.T) {
	body := `{"normalisedTargetFile":"broken/pom.xml","error":{"jsonapi":{"version":"1.0"},"errors":[{"id":"abc","status":"500","code":"SNYK-LEGACY-MOD-001","title":"Module failed","detail":"Could not resolve","meta":{"isErrorCatalogError":true,"classification":"ACTIONABLE"}}]}}`
	ictx, _ := setupLegacyCLI(t, body, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	require.Error(t, results[0].Error)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(results[0].Error, &snykErr))
	assert.Equal(t, "SNYK-LEGACY-MOD-001", snykErr.ErrorCode)
	assert.Equal(t, "Module failed", snykErr.Title)
}

func TestPlugin_PerResultCLIErrorIsPreservedWhenDepGraphIsMalformed(t *testing.T) {
	// Output carries both an upstream CLI error AND a malformed depgraph payload. The
	// CLI error is the user-meaningful one, so the unmarshal failure must not overwrite it.
	body := `{"normalisedTargetFile":"broken/pom.xml","depGraph":"not-valid-json","error":{"jsonapi":{"version":"1.0"},"errors":[{"id":"abc","status":"500","code":"SNYK-LEGACY-MOD-002","title":"Upstream failure","detail":"Module fetch failed","meta":{"isErrorCatalogError":true,"classification":"ACTIONABLE"}}]}}`
	ictx, _ := setupLegacyCLI(t, body, nil)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)

	require.Error(t, results[0].Error)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(results[0].Error, &snykErr), "upstream CLI error should be preserved, not overwritten by depgraph unmarshal failure")
	assert.Equal(t, "SNYK-LEGACY-MOD-002", snykErr.ErrorCode)
}

func TestPlugin_ExitCode3ReturnsNilSuccess(t *testing.T) {
	ictx := setupLegacyCLIWithError(t, exitCodeError{code: 3})
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results, "no-projects-found surfaces as no callback invocations")
}

func TestPlugin_ErrNoDepGraphsFoundReturnsNilSuccess(t *testing.T) {
	ictx := setupLegacyCLIWithEmptyData(t)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)
	assert.Empty(t, results, "no-projects-found surfaces as no callback invocations")
}

func TestPlugin_NonExitCode3ErrorIsWrapped(t *testing.T) {
	underlying := fmt.Errorf("network unreachable")
	ictx := setupLegacyCLIWithError(t, underlying)
	plugin := legacy.NewPlugin(ictx)

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error handling legacy workflow")
	assert.ErrorIs(t, err, underlying, "underlying error should remain in the chain via the snyk_errors.WithCause wrap")
	assert.Empty(t, results)
}

func TestPlugin_NilOptionsReturnsError(t *testing.T) {
	plugin := legacy.NewPlugin(nil)

	_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "options")
}

func TestPlugin_ExcludeBehaviour(t *testing.T) {
	t.Run("opts.Exclude is NOT forwarded to the legacy config", func(t *testing.T) {
		ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, nil)
		plugin := legacy.NewPlugin(ictx)

		opts := ecosystems.NewPluginOptions().WithExclude([]string{"a.lock", "b.lock"})
		_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", opts)
		require.NoError(t, err)

		assert.Equal(t, "", (*capturedConfig).GetString(workflow.FlagExclude),
			"opts.Exclude must not leak into the legacy CLI --exclude")
	})

	t.Run("user-supplied FlagExclude on the live config is preserved on the clone", func(t *testing.T) {
		preexisting := map[string]any{workflow.FlagExclude: "user-exclude.txt"}
		ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, preexisting)
		plugin := legacy.NewPlugin(ictx)

		opts := ecosystems.NewPluginOptions().WithExclude([]string{"a.lock"})
		_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", opts)
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
	_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", opts)
	require.NoError(t, err)

	assert.Equal(t, "user-exclude.txt", ictx.GetConfiguration().GetString(workflow.FlagExclude),
		"live config exclude should not be mutated; merge happens on a clone")
}

func TestPlugin_ForcesEffectiveGraphWithErrorsByDefault(t *testing.T) {
	ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, nil)
	plugin := legacy.NewPlugin(ictx)

	_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	assert.True(t, (*capturedConfig).GetBool(workflow.FlagPrintEffectiveGraphWithErrors))
}

func TestPlugin_DisablesEffectiveGraphWithErrorsWhenJSONLWithErrorsRequested(t *testing.T) {
	preexisting := map[string]any{workflow.FlagPrintOutputJsonlWithErrors: true}
	ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, preexisting)
	plugin := legacy.NewPlugin(ictx)

	_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", ecosystems.NewPluginOptions())
	require.NoError(t, err)

	assert.False(t, (*capturedConfig).GetBool(workflow.FlagPrintEffectiveGraphWithErrors))
	assert.True(t, (*capturedConfig).GetBool(workflow.FlagPrintOutputJsonlWithErrors))
}

// TestPlugin_BuildLegacyConfig_WritesExcludePathsFromOpts covers the contract:
// opts.Global.ExcludePaths is the canonical source for what the legacy CLI receives as
// --exclude-paths. When non-empty, it overrides any pre-existing FlagExcludePaths on the
// live config. When empty, the live config's value is preserved. (The override is
// lossless in every production path because the user's --exclude-paths is also on opts.)
func TestPlugin_BuildLegacyConfig_WritesExcludePathsFromOpts(t *testing.T) {
	cases := []struct {
		name                 string
		liveExcludePaths     string
		optsExcludePaths     []string
		expectedExcludePaths string
	}{
		{
			name:                 "empty opts and empty live leaves config empty",
			liveExcludePaths:     "",
			optsExcludePaths:     nil,
			expectedExcludePaths: "",
		},
		{
			name:                 "opts populated, live empty: opts written through",
			liveExcludePaths:     "",
			optsExcludePaths:     []string{"file1.py", "file2.py"},
			expectedExcludePaths: "file1.py,file2.py",
		},
		{
			name:                 "live populated, opts empty: live preserved (no opts to write)",
			liveExcludePaths:     "user-supplied.lock",
			optsExcludePaths:     nil,
			expectedExcludePaths: "user-supplied.lock",
		},
		{
			name:                 "both populated: opts overrides live (opts is canonical)",
			liveExcludePaths:     "user-supplied.lock",
			optsExcludePaths:     []string{"user-supplied.lock", "processed1.lock", "processed2.lock"},
			expectedExcludePaths: "user-supplied.lock,processed1.lock,processed2.lock",
		},
		{
			name:                 "single processed file",
			liveExcludePaths:     "",
			optsExcludePaths:     []string{"file1.py"},
			expectedExcludePaths: "file1.py",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preexisting := map[string]any{}
			if tc.liveExcludePaths != "" {
				preexisting[workflow.FlagExcludePaths] = tc.liveExcludePaths
			}
			ictx, capturedConfig := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, preexisting)
			plugin := legacy.NewPlugin(ictx)

			opts := ecosystems.NewPluginOptions()
			if len(tc.optsExcludePaths) > 0 {
				opts = opts.WithExcludePaths(tc.optsExcludePaths)
			}
			_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", opts)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedExcludePaths, (*capturedConfig).GetString(workflow.FlagExcludePaths))
		})
	}
}

// TestPlugin_BuildLegacyConfig_DoesNotMutateLiveConfigExcludePaths locks in the no-side-effect
// guarantee: the merge happens on the cloned config only.
func TestPlugin_BuildLegacyConfig_DoesNotMutateLiveConfigExcludePaths(t *testing.T) {
	preexisting := map[string]any{workflow.FlagExcludePaths: "user-supplied.lock"}
	ictx, _ := setupLegacyCLI(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`, preexisting)
	plugin := legacy.NewPlugin(ictx)

	opts := ecosystems.NewPluginOptions().WithExcludePaths([]string{"processed.lock"})
	_, err := scatest.Run(t.Context(), plugin, logger.Nop(), "", opts)
	require.NoError(t, err)

	assert.Equal(t, "user-supplied.lock", ictx.GetConfiguration().GetString(workflow.FlagExcludePaths),
		"live config FlagExcludePaths must not be mutated; merge happens on a clone")
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
