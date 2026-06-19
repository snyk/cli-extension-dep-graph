//go:build integration && pnpm
// +build integration,pnpm

package pnpm_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/pnpm"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// requirePnpm skips the test when pnpm is not installed. Run via:
//
//	make test-pnpm-integration   (go test -tags="integration,pnpm" ...)
func requirePnpm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pnpm"); err != nil {
		t.Skip("pnpm not in PATH")
	}
}

func run(t *testing.T, dir string) []ecosystems.SCAResult {
	t.Helper()
	results, err := scatest.Run(context.Background(), pnpm.Plugin{}, logger.Nop(), dir, ecosystems.NewPluginOptions())
	require.NoError(t, err)
	return results
}

func TestRushPnpm_SimpleVulnerableWorkspace(t *testing.T) {
	requirePnpm(t)
	results := run(t, filepath.Join("testdata", "simple-vulnerable-workspace"))

	// Two real projects; the synthetic "rush-common" importer is filtered out.
	require.Len(t, results, 2)

	byName := map[string]ecosystems.SCAResult{}
	for _, r := range results {
		require.NoError(t, r.Error)
		byName[r.ProjectDescriptor.Identity.RootComponentName] = r
	}
	require.Contains(t, byName, "@rush-fix/app-a")
	require.Contains(t, byName, "@rush-fix/lib-b")

	assert.Contains(t, graphJSON(t, byName["@rush-fix/app-a"]), "lodash@4.17.4")
	assert.Contains(t, graphJSON(t, byName["@rush-fix/lib-b"]), "minimatch@3.0.0")

	// targetFile points at the project's package.json, relative to the Rush root.
	assert.Equal(t, filepath.Join("apps", "app-a", "package.json"),
		byName["@rush-fix/app-a"].ProjectDescriptor.GetTargetFile())
}

// Standard (non-Rush) pnpm: a single-package project resolves directly via the
// pnpm-lock.yaml discovery path, no staging.
func TestStandalonePnpm(t *testing.T) {
	requirePnpm(t)
	results := run(t, filepath.Join("testdata", "standalone-pnpm"))

	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Equal(t, "standalone-pnpm-fixture", results[0].ProjectDescriptor.Identity.RootComponentName)
	assert.Equal(t, "package.json", results[0].ProjectDescriptor.GetTargetFile())
	assert.Contains(t, graphJSON(t, results[0]), "lodash@4.17.4")
}

// A project folder listed in rush.json but missing on disk (stale/renamed)
// must be skipped, not abort the whole monorepo scan.
func TestRushPnpm_MissingProjectIsSkippedNotFatal(t *testing.T) {
	requirePnpm(t)
	results := run(t, filepath.Join("testdata", "rush-missing-project"))

	// app-a + lib-b still resolved; the missing "ghost" project is skipped.
	require.Len(t, results, 2)
	for _, r := range results {
		require.NoError(t, r.Error)
	}
	names := map[string]bool{}
	for _, r := range results {
		names[r.ProjectDescriptor.Identity.RootComponentName] = true
	}
	assert.True(t, names["@rush-fix/app-a"] && names["@rush-fix/lib-b"])
	assert.False(t, names["@rush-fix/ghost"])
}

func TestRushPnpm_NonPnpmAndSubspacesAreSkipped(t *testing.T) {
	requirePnpm(t)
	for _, scenario := range []string{"rush-npm", "rush-yarn", "subspaces"} {
		t.Run(scenario, func(t *testing.T) {
			results := run(t, filepath.Join("testdata", scenario))
			assert.Empty(t, results, "%s should be skipped, not scanned", scenario)
		})
	}
}

// A subspaces.json that exists but has subspacesEnabled:false is NOT a
// subspaces repo — the monorepo-level lockfile is authoritative, so it must be
// scanned exactly like the baseline workspace. Regression guard for the
// file-exists-vs-field-value fix in rushSubspacesEnabled.
func TestRushPnpm_SubspacesDisabledIsScanned(t *testing.T) {
	requirePnpm(t)
	results := run(t, filepath.Join("testdata", "rush-subspaces-disabled"))

	require.Len(t, results, 2)
	names := map[string]bool{}
	for _, r := range results {
		require.NoError(t, r.Error)
		names[r.ProjectDescriptor.Identity.RootComponentName] = true
	}
	assert.True(t, names["@rush-fix/app-a"] && names["@rush-fix/lib-b"],
		"disabled-subspaces repo should resolve both projects, got %v", names)
}

func graphJSON(t *testing.T, r ecosystems.SCAResult) string {
	t.Helper()
	require.NotNil(t, r.DepGraph)
	b, err := json.Marshal(r.DepGraph)
	require.NoError(t, err)
	return strings.ToLower(string(b))
}
