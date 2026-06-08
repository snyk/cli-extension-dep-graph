//go:build integration && npm
// +build integration,npm

package npm_test

// legacy_fixtures_smoke_test.go runs the plugin against every imported
// fixture under testdata/legacy-fixtures/ and asserts the smallest
// possible "did it work" contract:
//
//   * BuildDepGraphsFromDir returns no setup error
//   * exactly one SCAResult per non-workspace fixture, ≥ 2 for workspaces
//   * each result has a non-nil DepGraph and no per-result Error
//   * the root pkg name from the dep graph matches the fixture's package.json
//
// Divergence vs. the legacy parser's output is measured separately by
// legacy_divergence_test.go — this file just checks the plugin produces
// *something* sensible.
//
// Fixtures whose lockfile requires a newer npm than the host are skipped
// via requireFixtureCompat (see fixture_helpers_test.go).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/javascript/npm"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// expectedToError is the set of fixture IDs (category/name) that intentionally
// model broken inputs in the upstream parser's test corpus — malformed JSON,
// missing names, undefined deps. Our plugin surfaces npm's error for these
// rather than synthesising placeholder nodes, so they are not smoke-testable
// without an explicit error-contract that we don't yet have.
//
// Each entry should grow an explicit "expects error X" test when we add the
// error-contract layer.
var expectedToError = map[string]string{
	"general/invalid-files":              "package-lock.json is intentionally malformed",
	"general/missing-name":               "package.json omits required name field",
	"general/package-json-without-name":  "package.json omits required name field",
	"general/undefined-deps":             "lockfile references packages it does not define",
}

func TestLegacyFixtures_Smoke(t *testing.T) {
	fixtures := discoverLegacyFixtures(t)
	require.NotEmpty(t, fixtures, "no fixtures discovered under %s", legacyFixturesRoot)

	t.Logf("discovered %d fixtures", len(fixtures))

	plugin := npm.Plugin{}

	for _, fx := range fixtures {
		t.Run(fx.ID(), func(t *testing.T) {
			if reason, ok := expectedToError[fx.ID()]; ok {
				t.Skipf("expected-to-error fixture (no error-contract test yet): %s", reason)
			}

			requireFixtureCompat(t, fx)

			results, err := scatest.Run(context.Background(), plugin, nil, fx.Dir, &ecosystems.SCAPluginOptions{})
			require.NoError(t, err, "plugin returned setup-time error")
			require.NotEmpty(t, results, "plugin returned zero SCAResults")

			// Surface per-result errors with the fixture ID so failures are easy to triage.
			for i, r := range results {
				if r.Error != nil {
					t.Errorf("result[%d] errored: %v", i, r.Error)
					continue
				}
				require.NotNil(t, r.DepGraph, "result[%d] has nil DepGraph despite no error", i)
			}

			// Workspaces produce ≥ 2 results (root + ≥1 workspace). We don't
			// hardcode the exact count — that's verified by category-specific
			// tests if needed.
			if isWorkspaceFixture(t, fx) {
				assert.GreaterOrEqual(t, len(results), 2,
					"workspace fixture should produce root + ≥1 workspace dep graph")
			} else {
				assert.Len(t, results, 1, "non-workspace fixture should produce exactly one dep graph")
			}

			// Root component name should match the fixture's package.json name.
			rootName := readRootPackageName(t, fx.Dir)
			if rootName != "" && len(results) > 0 && results[0].DepGraph != nil {
				assert.Equal(t, rootName, results[0].DepGraph.GetRootPkg().Info.Name,
					"root component name should match package.json name")
			}
		})
	}
}

// isWorkspaceFixture returns true if the fixture's root package.json declares
// a workspaces array. Uses a permissive parse — workspaces may be an array
// of globs or an object containing one.
func isWorkspaceFixture(t *testing.T, fx legacyFixture) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fx.Dir, "package.json"))
	if err != nil {
		return false
	}
	var shape struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &shape); err != nil {
		return false
	}
	return len(shape.Workspaces) > 0 && string(shape.Workspaces) != "null"
}

// readRootPackageName returns the "name" field of the fixture's root
// package.json, or "" if the file is unreadable or has no name field.
func readRootPackageName(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return ""
	}
	var shape struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &shape); err != nil {
		return ""
	}
	return strings.TrimSpace(shape.Name)
}
