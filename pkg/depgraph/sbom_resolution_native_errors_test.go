package depgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/legacy"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
)

func Test_handleSBOMResolution_nativeReturnedError(t *testing.T) {
	cases := []struct {
		name        string
		allProjects bool
		failFast    bool
		wantError   bool
	}{
		{name: "all projects preserves other ecosystems", allProjects: true},
		{name: "default surfaces native error", wantError: true},
		{name: "fail fast stops before other ecosystems", allProjects: true, failFast: true, wantError: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestContext(t, false)
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "build.gradle"), nil, 0o600))
			report := filepath.Join(dir, "invalid.ndjson")
			require.NoError(t, os.WriteFile(report, []byte("invalid json"), 0o600))
			binaries := t.TempDir()
			script := fmt.Sprintf("#!/bin/sh\nprintf 'SNYK_DEPS_NDJSON %%s\\n' '%s'\n", report)
			require.NoError(t, os.WriteFile(filepath.Join(binaries, "gradle"), []byte(script), 0o600))
			require.NoError(t, os.Chmod(filepath.Join(binaries, "gradle"), 0o700))
			t.Setenv("PATH", binaries)
			tc.config.Set(configuration.INPUT_DIRECTORY, dir)
			tc.config.Set(workflow.FlagAllProjects, tt.allProjects)
			tc.config.Set(workflow.FlagFailFast, tt.failFast)
			tc.config.Set(orchestrator.FlagNewGradleResolver.Key, true)
			if !tt.wantError {
				tc.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...ui.Opts) error {
					assert.Contains(t, err.Error(), "1/3 potential projects failed")
					return nil
				})
			}
			harness := NewLegacyHarness(tc)
			harness.ReturnTargets = []string{"package.json"}
			uv := &mockScaPlugin{name: "uv", results: []ecosystems.SCAResult{{
				DepGraph:         createTestDepGraph(t, "uv", "python-app", "1.0.0"),
				ResolverMetadata: &ecosystems.ResolverMetadata{PluginName: "uv", NormalisedTargetFile: "pyproject.toml"},
			}}}
			registry, err := orchestrator.NewDefaultPluginRegistry(tc.invocationContext)
			require.NoError(t, err)

			data, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, registry.Plugins().With(uv).With(legacy.NewPlugin(tc.invocationContext)))

			assert.Equal(t, !tt.wantError, uv.options != nil)
			assert.Equal(t, !tt.wantError, harness.Called())
			if tt.wantError {
				require.ErrorContains(t, err, "failed to parse init script output")
				assert.Empty(t, data)
				if tt.failFast {
					var exitErr interface{ ExitCode() int }
					require.ErrorAs(t, err, &exitErr)
					assert.Equal(t, 2, exitErr.ExitCode())
				}
				return
			}
			require.NoError(t, err)
			require.Len(t, data, 2)
			assert.Equal(t, "pyproject.toml", metaString(t, data[0], workflow.MetaKeyNormalisedTargetFile))
			assert.Equal(t, "package.json", metaString(t, data[1], workflow.MetaKeyNormalisedTargetFile))
		})
	}
}

func Test_handleSBOMResolution_nativeEmittedErrorWithoutMetadata(t *testing.T) {
	cases := []struct {
		name                  string
		allProjects, failFast bool
	}{
		{name: "all projects preserves UV and legacy", allProjects: true},
		{name: "default surfaces native error"},
		{name: "failfast reports manifest", allProjects: true, failFast: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tc := setupTestContext(t, false)
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "build.gradle"), nil, 0o600))
			t.Setenv("PATH", t.TempDir())
			tc.config.Set(configuration.INPUT_DIRECTORY, dir)
			tc.config.Set(workflow.FlagAllProjects, tt.allProjects)
			tc.config.Set(workflow.FlagFailFast, tt.failFast)
			tc.config.Set(workflow.FlagUseSBOMResolution, true)
			tc.config.Set(orchestrator.FlagNewGradleResolver.Key, true)
			if tt.allProjects && !tt.failFast {
				tc.userInterface.EXPECT().OutputError(gomock.Any()).DoAndReturn(func(err error, _ ...ui.Opts) error {
					assert.Contains(t, err.Error(), "build.gradle")
					assert.Contains(t, err.Error(), "1/3 potential projects failed")
					return nil
				})
			}
			harness := NewLegacyHarness(tc)
			harness.ReturnTargets = []string{"package.json"}
			uv := &mockScaPlugin{name: "uv", results: []ecosystems.SCAResult{{
				DepGraph:         createTestDepGraph(t, "uv", "python-app", "1.0.0"),
				ResolverMetadata: &ecosystems.ResolverMetadata{PluginName: "uv", NormalisedTargetFile: "pyproject.toml"},
			}}}
			registry, err := orchestrator.NewDefaultPluginRegistry(tc.invocationContext)
			require.NoError(t, err)

			data, err := handleSBOMResolutionDI(tc.invocationContext, tc.config, &nopLogger, registry.Plugins().With(uv).With(legacy.NewPlugin(tc.invocationContext)))

			if !tt.allProjects || tt.failFast {
				require.Error(t, err)
				assert.Empty(t, data)
				if tt.failFast {
					require.ErrorContains(t, err, "Failed to scan build.gradle")
					var exitErr interface{ ExitCode() int }
					require.ErrorAs(t, err, &exitErr)
					assert.Equal(t, 2, exitErr.ExitCode())
				}
				assert.False(t, harness.Called())
				assert.Nil(t, uv.options)
				return
			}
			require.NoError(t, err)
			require.Len(t, data, 2)
			assert.Equal(t, "pyproject.toml", metaString(t, data[0], workflow.MetaKeyNormalisedTargetFile))
			assert.Equal(t, "package.json", metaString(t, data[1], workflow.MetaKeyNormalisedTargetFile))
		})
	}
}
