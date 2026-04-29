//go:build integration && gradle
// +build integration,gradle

package gradle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
)

// updateFixturesEnvVar, when set to a truthy value, causes the integration tests
// to write captured plugin results back to expected_plugin.json fixtures rather
// than asserting against them.  Use via `UPDATE_FIXTURES=1 make test-gradle-integration`.
const updateFixturesEnvVar = "UPDATE_FIXTURES"

// fixturesRoot is the path to the shared gradle fixtures directory, relative to
// the gradle package.
var fixturesRoot = filepath.Join("..", "testdata", "fixtures", "gradle")

// PluginTestCase defines an integration test invocation.
type PluginTestCase struct {
	Fixture string
	Options *ecosystems.SCAPluginOptions
	// ExpectedFile overrides the default `expected_plugin.json` filename.
	// Useful when multiple cases share a fixture but produce different outputs
	// (e.g. full vs target-file scans).
	ExpectedFile string
}

// pluginTestCases enumerates the integration scenarios. Each fixture directory
// under pkg/ecosystems/testdata/fixtures/gradle/ owns its expected_plugin*.json
// file(s); see assertResultsMatchExpected for the comparison rules.
func pluginTestCases() map[string]PluginTestCase {
	return map[string]PluginTestCase{
		"simple_full_scan": {
			Fixture: "simple",
			Options: ecosystems.NewPluginOptions(),
		},
		"simple_target_file": {
			Fixture:      "simple",
			Options:      ecosystems.NewPluginOptions().WithTargetFile("build.gradle"),
			ExpectedFile: "expected_plugin_target_file.json",
		},
		"multi_module_full_scan": {
			Fixture: "multi-module",
			Options: ecosystems.NewPluginOptions(),
		},
		"multi_module_target_file_app": {
			Fixture:      "multi-module",
			Options:      ecosystems.NewPluginOptions().WithTargetFile("app/build.gradle"),
			ExpectedFile: "expected_plugin_target_file_app.json",
		},
		"multi_module_target_file_lib": {
			Fixture:      "multi-module",
			Options:      ecosystems.NewPluginOptions().WithTargetFile("lib/build.gradle"),
			ExpectedFile: "expected_plugin_target_file_lib.json",
		},
	}
}

// TestPlugin_BuildDepGraphsFromDir runs the gradle plugin against each fixture
// and compares the captured results against the corresponding expected JSON
// snapshot. When UPDATE_FIXTURES=1 is set the snapshot is rewritten instead.
func TestPlugin_BuildDepGraphsFromDir(t *testing.T) {
	updateFixtures := os.Getenv(updateFixturesEnvVar) != ""

	for name, testCase := range pluginTestCases() {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			fixturePath := filepath.Join(fixturesRoot, testCase.Fixture)
			absFixture, err := filepath.Abs(fixturePath)
			require.NoError(t, err, "failed to resolve fixture path")

			plugin := Plugin{}
			result, err := plugin.BuildDepGraphsFromDir(ctx, logger.Nop(), absFixture, testCase.Options)
			require.NoError(t, err, "BuildDepGraphsFromDir should not return error")
			require.NotNil(t, result, "plugin result should not be nil")

			expectedPath := filepath.Join(fixturePath, expectedFileName(testCase))

			if updateFixtures {
				writeExpectedSnapshot(t, expectedPath, result.Results)
				return
			}

			expected := loadExpectedResults(t, expectedPath)
			assertResultsMatchExpected(t, result.Results, expected, testCase.Fixture)
		})
	}
}

// expectedFileName returns the filename for the expected snapshot of a test case.
func expectedFileName(testCase PluginTestCase) string {
	if testCase.ExpectedFile != "" {
		return testCase.ExpectedFile
	}
	return "expected_plugin.json"
}

// loadExpectedResults reads the expected snapshot from disk. Tests fail if the
// file is missing — run with UPDATE_FIXTURES=1 to generate it.
func loadExpectedResults(t *testing.T, path string) []ecosystems.SCAResult {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoErrorf(t, err, "failed to read expected snapshot %s; run with %s=1 to generate", path, updateFixturesEnvVar)

	var expected []ecosystems.SCAResult
	require.NoErrorf(t, json.Unmarshal(data, &expected), "failed to parse expected snapshot %s", path)

	return expected
}

// writeExpectedSnapshot serialises the captured results to disk so they can be
// reviewed and committed as the new fixture.
func writeExpectedSnapshot(t *testing.T, path string, results []ecosystems.SCAResult) {
	t.Helper()

	data, err := json.MarshalIndent(results, "", "  ")
	require.NoError(t, err, "failed to marshal results for snapshot")

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755), "failed to create snapshot directory")
	require.NoError(t, os.WriteFile(path, append(data, '\n'), 0o644), "failed to write snapshot file")

	t.Logf("Updated snapshot: %s", path)
}

// assertResultsMatchExpected compares actual against expected via JSON equality.
// Volatile fields that depend on the host JDK / Gradle distribution are synced
// from actual into expected before comparison so fixtures stay portable across
// the (gradle, jdk) matrix used in CI.
func assertResultsMatchExpected(t *testing.T, actual, expected []ecosystems.SCAResult, fixture string) {
	t.Helper()

	require.Lenf(t, actual, len(expected), "[%s] result count mismatch", fixture)

	sortedActual := sortResults(actual)
	sortedExpected := sortResults(expected)

	for i := range sortedExpected {
		// TargetRuntime is not currently emitted by the gradle plugin, but if
		// it ever starts varying with the JDK we want to ignore that here.
		sortedExpected[i].ProjectDescriptor.Identity.TargetRuntime = sortedActual[i].ProjectDescriptor.Identity.TargetRuntime
		// Error is not part of the snapshot format.
		sortedActual[i].Error = nil
	}

	actualJSON, err := json.Marshal(sortedActual)
	require.NoErrorf(t, err, "[%s] failed to marshal actual results", fixture)

	expectedJSON, err := json.Marshal(sortedExpected)
	require.NoErrorf(t, err, "[%s] failed to marshal expected results", fixture)

	resolvedExpected, err := resolveWildcardVersions(expectedJSON, actualJSON)
	require.NoErrorf(t, err, "[%s] failed to resolve wildcard versions", fixture)

	assert.JSONEq(t, string(resolvedExpected), string(actualJSON), "[%s] results mismatch", fixture)
}

// sortResults returns a copy of results sorted by target file (with root
// component name as a tiebreaker) to make comparisons deterministic.
func sortResults(results []ecosystems.SCAResult) []ecosystems.SCAResult {
	sorted := make([]ecosystems.SCAResult, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		ti := sorted[i].ProjectDescriptor.GetTargetFile()
		tj := sorted[j].ProjectDescriptor.GetTargetFile()
		if ti != tj {
			return ti < tj
		}
		return sorted[i].ProjectDescriptor.Identity.RootComponentName < sorted[j].ProjectDescriptor.Identity.RootComponentName
	})
	return sorted
}

// resolveWildcardVersions substitutes wildcard versions ("*") in expectedJSON
// with the actual resolved versions from actualJSON. This keeps fixtures
// resilient to patch-level transitive bumps from Maven Central without losing
// graph-shape coverage.
func resolveWildcardVersions(expectedJSON, actualJSON []byte) ([]byte, error) {
	var actualResults []any
	if err := json.Unmarshal(actualJSON, &actualResults); err != nil {
		return nil, fmt.Errorf("failed to unmarshal actual results: %w", err)
	}

	var expectedResults []any
	if err := json.Unmarshal(expectedJSON, &expectedResults); err != nil {
		return nil, fmt.Errorf("failed to unmarshal expected results: %w", err)
	}

	if len(actualResults) != len(expectedResults) {
		// Mismatched counts are surfaced by the caller; return expected unchanged
		// so the JSONEq diff is still meaningful.
		return expectedJSON, nil
	}

	for i := range expectedResults {
		actualResult, ok := actualResults[i].(map[string]any)
		if !ok {
			continue
		}
		expectedResult, ok := expectedResults[i].(map[string]any)
		if !ok {
			continue
		}
		nameToVersion := extractNameVersionMap(actualResult)
		substituteWildcards(expectedResult, nameToVersion)
	}

	return json.Marshal(expectedResults)
}

// extractNameVersionMap builds a map of package name -> resolved version from
// the "pkgs" list of a single result's depGraph.
func extractNameVersionMap(result map[string]any) map[string]string {
	nameToVersion := make(map[string]string)
	depGraph, ok := result["depGraph"].(map[string]any)
	if !ok {
		return nameToVersion
	}
	pkgs, ok := depGraph["pkgs"].([]any)
	if !ok {
		return nameToVersion
	}
	for _, pkg := range pkgs {
		pkgMap, ok := pkg.(map[string]any)
		if !ok {
			continue
		}
		id, ok := pkgMap["id"].(string)
		if !ok {
			continue
		}
		atIdx := strings.LastIndex(id, "@")
		if atIdx < 0 {
			continue
		}
		nameToVersion[id[:atIdx]] = id[atIdx+1:]
	}
	return nameToVersion
}

// substituteWildcards replaces wildcard version markers ("*") in the expected
// JSON structure with the corresponding actual versions. Mirrors the helper
// used in the python integration tests.
func substituteWildcards(v any, nameToVersion map[string]string) {
	switch node := v.(type) {
	case map[string]any:
		if version, ok := node["version"].(string); ok && version == "*" {
			if name, ok := node["name"].(string); ok {
				if actualVersion, found := nameToVersion[name]; found {
					node["version"] = actualVersion
				}
			}
		}
		for _, key := range []string{"id", "nodeId", "pkgId"} {
			if s, ok := node[key].(string); ok {
				if idx := strings.Index(s, "@*"); idx >= 0 {
					name := s[:idx]
					suffix := s[idx+2:]
					if actualVersion, found := nameToVersion[name]; found {
						node[key] = name + "@" + actualVersion + suffix
					}
				}
			}
		}
		for _, val := range node {
			substituteWildcards(val, nameToVersion)
		}
	case []any:
		for _, item := range node {
			substituteWildcards(item, nameToVersion)
		}
	}
}
