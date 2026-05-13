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

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/metadata"
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
		"simple_modern_deps_full_scan": {
			Fixture: "simple-modern-deps",
			Options: ecosystems.NewPluginOptions(),
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
		// Exercises TOML version catalog (libs.versions.toml) parsing. Gradle 7+ only.
		"version_catalog": {
			Fixture: "version-catalog",
			Options: ecosystems.NewPluginOptions(),
		},
		// Exercises dependency locking with dynamic versions and version ranges
		// resolved against a checked-in gradle.lockfile.
		"with_lock_file": {
			Fixture: "with-lock-file",
			Options: ecosystems.NewPluginOptions(),
		},
		// Exercises Maven BOM resolution via `implementation platform(...)` where
		// transitive coordinates inherit versions from the BOM.
		"platform_bom": {
			Fixture: "platform-bom",
			Options: ecosystems.NewPluginOptions(),
		},
		// Exercises the `constraints {}` DSL: pins the resolved version of a
		// transitive dep without declaring a real edge. Asserts the constraint
		// edge surfaces as a `:constraint`-suffixed leaf and does not poison
		// the visited set for the real transitive edge to the same module.
		"dependency_constraints": {
			Fixture: "dependency-constraints",
			Options: ecosystems.NewPluginOptions(),
		},
		// Regression fixture for resolutionStrategy.force. `force` is a
		// version-selection rule, not a constraint edge — the forced module
		// must appear as a normal node, never as a `:constraint` leaf.
		"version_forcing": {
			Fixture: "version-forcing",
			Options: ecosystems.NewPluginOptions(),
		},
		// Regression fixture for dependencySubstitution. Substitution replaces
		// the target component on an existing edge — the substituted module
		// must appear as a normal node, never as a `:constraint` leaf.
		"dependency_substitution": {
			Fixture: "dependency-substitution",
			Options: ecosystems.NewPluginOptions(),
		},
		// Smoke test that the Kotlin DSL build file (build.gradle.kts) is
		// discovered and resolved equivalently to its Groovy counterpart.
		"kts_simple": {
			Fixture: "kts-simple",
			Options: ecosystems.NewPluginOptions(),
		},
		// Exercises Maven artifact classifiers. Gradle's resolution result keys
		// off GAV so both classifier variants collapse to a single component.
		"classifiers": {
			Fixture: "classifiers",
			Options: ecosystems.NewPluginOptions(),
		},
		// Exercises three subprojects where two share the simple name "subproj"
		// (one at :subproj, one at :greeter:subproj) — verifies project paths
		// disambiguate and that targetFile uniqueness is preserved.
		"same_name_subprojects": {
			Fixture: "same-name-subprojects",
			Options: ecosystems.NewPluginOptions(),
		},
		// Exercises dynamic version selectors (range `[a, b)`, open `+`) and
		// resolutionStrategy.force. Resolved versions are wildcarded in the
		// snapshot to stay resilient to Maven Central transitive bumps.
		"dynamic_versions": {
			Fixture: "dynamic-versions",
			Options: ecosystems.NewPluginOptions(),
		},
		// Exercises --configuration-matching flag functionality using a fixture with dependencies
		// in multiple configurations: implementation (guava), runtimeOnly (logback), compileOnly (commons-lang3),
		// testImplementation (junit, mockito), and testRuntimeOnly (slf4j-simple).
		// This validates that the regex filtering correctly includes/excludes configurations.

		// Full scan (baseline) - includes all configurations
		"configuration_matching_full_scan": {
			Fixture: "configuration-matching",
			Options: ecosystems.NewPluginOptions(),
		},
		// Runtime configurations only - includes implementation + runtimeOnly + testRuntimeOnly
		"configuration_matching_runtime_only": {
			Fixture:      "configuration-matching",
			Options:      ecosystems.NewPluginOptions().WithGradleConfigurationMatching("(?i).*runtime.*"),
			ExpectedFile: "expected_plugin_runtime_only.json",
		},
		// Compile configurations only - includes compileOnly + compileClasspath
		"configuration_matching_compile_only": {
			Fixture:      "configuration-matching",
			Options:      ecosystems.NewPluginOptions().WithGradleConfigurationMatching("compile.*"),
			ExpectedFile: "expected_plugin_compile_only.json",
		},
		// Test configurations only - includes testImplementation + testRuntimeOnly
		"configuration_matching_test_only": {
			Fixture:      "configuration-matching",
			Options:      ecosystems.NewPluginOptions().WithGradleConfigurationMatching("(?i)test.*"),
			ExpectedFile: "expected_plugin_test_only.json",
		},
		// Exact match for single configuration - includes only runtimeClasspath
		"configuration_matching_exact": {
			Fixture:      "configuration-matching",
			Options:      ecosystems.NewPluginOptions().WithGradleConfigurationMatching("^runtimeClasspath$"),
			ExpectedFile: "expected_plugin_exact_runtime.json",
		},
		// Exercises nested BOM resolution with complex constraint hierarchy.
		// Validates that imported BOMs produce `:constraint` leaves while
		// allowing the real dependency paths to be fully expanded.
		"nested_bom_constraints": {
			Fixture: "nested-bom-constraints",
			Options: ecosystems.NewPluginOptions(),
		},
		// Multi-module project with platform BOM that imports external BOMs.
		// Demonstrates nested BOM hierarchy where platform -> external BOMs
		// -> component constraints, ensuring proper DAG structure.
		"multi_module_bom": {
			Fixture: "multi-module-bom",
			Options: ecosystems.NewPluginOptions(),
		},
	}
}

// TestGradleWrapper_BinaryResolution validates that the plugin correctly chooses
// between wrapper and system gradle binaries based on options and fixture setup.
// These tests focus on execution path and metadata, not graph content (which is
// identical regardless of gradle binary version).
func TestGradleWrapper_BinaryResolution(t *testing.T) {
	// Check JDK compatibility - Gradle 8.4 (used by wrapper) supports at most Java 21
	jdkVersion, err := jdkRuntime()
	require.NoErrorf(t, err, "could not detect jdk runtime version")

	if jdkVersion.Major() > 21 {
		t.Skipf("Gradle 8.4 wrapper supports at most Java 21; running on Java %d", jdkVersion.Major())
	}

	wrapperFixture := filepath.Join(fixturesRoot, "with-wrapper")
	absFixture, err := filepath.Abs(wrapperFixture)
	require.NoError(t, err, "failed to resolve wrapper fixture path")

	plugin := Plugin{}
	ctx := context.Background()

	testCases := []struct {
		name                string
		options             *ecosystems.SCAPluginOptions
		expectedVersionFunc func() string
		versionDescription  string
	}{
		{
			name:                "uses_wrapper_binary",
			options:             ecosystems.NewPluginOptions(),
			expectedVersionFunc: func() string { return "8.4" },
			versionDescription:  "should use wrapper Gradle 8.4, not system gradle",
		},
		{
			name:    "skip_wrapper_uses_system",
			options: ecosystems.NewPluginOptions().WithGradleSkipWrapper(true),
			expectedVersionFunc: func() string {
				systemVersion, err := gradleRuntime()
				if err != nil {
					return ""
				}
				return systemVersion.String()
			},
			versionDescription: "should use detected system gradle version",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := plugin.BuildDepGraphsFromDir(ctx, logger.Nop(), absFixture, tc.options)

			require.NoError(t, err, "gradle execution should succeed")
			require.Len(t, result.Results, 1, "should process one project")

			// Assert gradle version from ResolverMetadata
			require.NotNil(t, result.Results[0].ResolverMetadata, "metadata should be populated")
			require.NotNil(t, result.Results[0].ResolverMetadata.VersionBuildInfo, "version build info should be populated")

			actualGradleVersion := result.Results[0].ResolverMetadata.VersionBuildInfo[metadata.GradleVersion]
			expectedVersion := tc.expectedVersionFunc()
			if expectedVersion == "" {
				t.Fatalf("failed to get expected gradle version for test case %q", tc.name)
			}
			assert.Equal(t, expectedVersion, actualGradleVersion, tc.versionDescription)

			// Ensure basic execution works
			assert.Equal(t, "com.snyk.fixtures:with-wrapper", result.Results[0].ProjectDescriptor.Identity.RootComponentName)
			require.NotNil(t, result.Results[0].DepGraph, "dependency graph should be built")
		})
	}
}

// TestPlugin_BuildDepGraphsFromDir runs the gradle plugin against each fixture
// and compares the captured results against the corresponding expected JSON
// snapshot. When UPDATE_FIXTURES=1 is set the snapshot is rewritten instead.
func TestPlugin_BuildDepGraphsFromDir(t *testing.T) {
	updateFixtures := os.Getenv(updateFixturesEnvVar) != ""

	gradleVersion, err := gradleRuntime()
	require.NoErrorf(t, err, "could not detect gradle runtime version")
	jdkVersion, err := jdkRuntime()
	require.NoErrorf(t, err, "could not detect jdk runtime version")
	t.Logf("gradle %s / jdk %s", gradleVersion, jdkVersion)

	for name, testCase := range pluginTestCases() {
		t.Run(name, func(t *testing.T) {
			fixturePath := filepath.Join(fixturesRoot, testCase.Fixture)
			absFixture, err := filepath.Abs(fixturePath)
			require.NoError(t, err, "failed to resolve fixture path")

			meta, err := loadFixtureMetadata(absFixture)
			require.NoErrorf(t, err, "failed to load metadata for fixture %q", testCase.Fixture)

			if reason, err := meta.skipReason(gradleVersion, jdkVersion); err != nil {
				t.Fatalf("invalid metadata for fixture %q: %v", testCase.Fixture, err)
			} else if reason != "" {
				t.Skipf("fixture %q not applicable: %s", testCase.Fixture, reason)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			plugin := Plugin{}
			result, err := plugin.BuildDepGraphsFromDir(ctx, logger.Nop(), absFixture, testCase.Options)
			require.NoError(t, err, "BuildDepGraphsFromDir should not return error")
			require.NotNil(t, result, "plugin result should not be nil")

			if updateFixtures {
				writeExpectedSnapshot(t, filepath.Join(fixturePath, defaultExpectedFileName(testCase)), result.Results)
				return
			}

			expectedPath, err := resolveExpectedSnapshotPath(fixturePath, testCase, gradleVersion)
			require.NoErrorf(t, err, "no expected snapshot for fixture %q; run with %s=1 to generate", testCase.Fixture, updateFixturesEnvVar)

			expected := loadExpectedResults(t, expectedPath)
			assertResultsMatchExpected(t, result.Results, expected, testCase.Fixture)
		})
	}
}

// defaultExpectedFileName returns the snapshot filename used when writing
// fresh fixtures via UPDATE_FIXTURES=1. We always write the version-agnostic
// name; humans can rename / split into version-specific snapshots when a
// fixture's output starts diverging across runtime versions.
func defaultExpectedFileName(testCase PluginTestCase) string {
	if testCase.ExpectedFile != "" {
		return testCase.ExpectedFile
	}
	return "expected_plugin.json"
}

// resolveExpectedSnapshotPath returns the path of the expected snapshot to
// compare against, preferring a version-specific file over the generic
// fallback. For a test case whose default snapshot is "expected_plugin.json"
// running on Gradle 8.x, the lookup order is:
//
//	expected_plugin_gradle8.json    (major-pinned version-specific snapshot)
//	expected_plugin.json            (version-agnostic fallback)
//
// If the test case overrides the snapshot via ExpectedFile (e.g.
// "expected_plugin_target_file_app.json"), the same suffixing rule is applied
// before the .json extension:
//
//	expected_plugin_target_file_app_gradle8.json
//	expected_plugin_target_file_app.json
func resolveExpectedSnapshotPath(fixtureDir string, testCase PluginTestCase, gradleVersion *semver.Version) (string, error) {
	defaultName := defaultExpectedFileName(testCase)
	candidates := []string{
		insertVersionSuffix(defaultName, fmt.Sprintf("gradle%d", gradleVersion.Major())),
		defaultName,
	}
	for _, name := range candidates {
		path := filepath.Join(fixtureDir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no expected snapshot found in %s (tried %v)", fixtureDir, candidates)
}

// insertVersionSuffix inserts "_<suffix>" before the .json extension. If the
// filename has no extension, the suffix is appended.
func insertVersionSuffix(name, suffix string) string {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	return stem + "_" + suffix + ext
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

	// Clean volatile fields before writing snapshot
	cleaned := make([]ecosystems.SCAResult, len(results))
	copy(cleaned, results)
	for i := range cleaned {
		// Error is not part of the snapshot format.
		cleaned[i].Error = nil
		// ResolverMetadata contains runtime-specific info and is not part of the snapshot format.
		cleaned[i].ResolverMetadata = nil
	}

	data, err := json.MarshalIndent(cleaned, "", "  ")
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
		// Error is not part of the snapshot format.
		sortedActual[i].Error = nil
		// ResolverMetadata contains runtime-specific info and is not part of the snapshot format.
		sortedActual[i].ResolverMetadata = nil
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
