//go:build integration && python
// +build integration,python

package pip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	snykerrors "github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

// PluginTestCase defines a test case for the plugin
type PluginTestCase struct {
	Fixture string                       // Fixture directory name
	Options *ecosystems.SCAPluginOptions // Plugin options
}

// TestPlugin_BuildDepGraphsFromDir tests the plugin with various fixtures
func TestPlugin_BuildDepGraphsFromDir(t *testing.T) {
	// Get Python version once for all tests
	pythonVersion, err := getPythonMajorMinorVersion()
	if err != nil {
		t.Logf("Warning: failed to get Python version: %v", err)
		pythonVersion = ""
	}

	tests := map[string]PluginTestCase{
		"single_requirements_at_root":           {Fixture: "simple", Options: ecosystems.NewPluginOptions()},
		"empty_requirements":                    {Fixture: "empty", Options: ecosystems.NewPluginOptions()},
		"multiple_dependencies":                 {Fixture: "multiple-deps", Options: ecosystems.NewPluginOptions()},
		"with_version_specifiers":               {Fixture: "with-version-specifiers", Options: ecosystems.NewPluginOptions()},
		"with_extras":                           {Fixture: "with-extras", Options: ecosystems.NewPluginOptions()},
		"os_specific_requirements":              {Fixture: "os-specific", Options: ecosystems.NewPluginOptions()},
		"environment_markers":                   {Fixture: "env-markers", Options: ecosystems.NewPluginOptions()},
		"git_references":                        {Fixture: "git-references", Options: ecosystems.NewPluginOptions()},
		"url_references":                        {Fixture: "url-references", Options: ecosystems.NewPluginOptions()},
		"multiple_requirements_all_subprojects": {Fixture: "multi-requirements", Options: ecosystems.NewPluginOptions().WithAllSubProjects(true)},
		"transitive_conflicts":                  {Fixture: "transitive-conflicts", Options: ecosystems.NewPluginOptions()},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			// Get fixture path
			fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "python", tc.Fixture)
			absPath, err := filepath.Abs(fixturePath)
			require.NoError(t, err, "failed to get absolute path for fixture")

			// Run plugin
			plugin := Plugin{}
			results, err := plugin.BuildDepGraphsFromDir(ctx, absPath, tc.Options)
			require.NoError(t, err, "BuildDepGraphsFromDir should not return error")

			// Load and compare expected output
			expectedPath := getExpectedOutputPath(t, fixturePath, pythonVersion)
			require.NotEmpty(t, expectedPath, "no expected output file found for fixture %s", tc.Fixture)

			expected, err := loadExpectedResults(expectedPath)
			require.NoError(t, err, "failed to load expected output from %s", expectedPath)

			assertResultsMatchExpected(t, results, expected, tc.Fixture)
		})
	}
}

// TestPlugin_Concurrency tests that concurrent execution works correctly
func TestPlugin_Concurrency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Get Python version
	pythonVersion, err := getPythonMajorMinorVersion()
	if err != nil {
		t.Logf("Warning: failed to get Python version: %v", err)
		pythonVersion = ""
	}

	fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "python", "multi-requirements")
	absPath, err := filepath.Abs(fixturePath)
	require.NoError(t, err)

	plugin := Plugin{}
	options := ecosystems.NewPluginOptions().WithAllSubProjects(true)

	// Load expected output once
	expectedPath := getExpectedOutputPath(t, fixturePath, pythonVersion)
	require.NotEmpty(t, expectedPath, "no expected output file found")
	expected, err := loadExpectedResults(expectedPath)
	require.NoError(t, err)

	// Run multiple times to test race conditions
	for i := 0; i < 5; i++ {
		results, err := plugin.BuildDepGraphsFromDir(ctx, absPath, options)
		require.NoError(t, err, "iteration %d failed", i)
		assertResultsMatchExpected(t, results, expected, "multi-requirements")
	}
}

// TestPlugin_BuildDepGraphsFromDir_PipErrors verifies that pip failures for different
// requirements fixtures are surfaced as catalog errors on the SCAResult rather than
// failing the whole plugin call.
func TestPlugin_BuildDepGraphsFromDir_PipErrors(t *testing.T) {
	pythonVersion, err := getPythonMajorMinorVersion()
	if err != nil {
		t.Logf("Warning: failed to get Python version: %v", err)
		pythonVersion = ""
	}

	tests := map[string]struct {
		fixture               string
		expectedCode          string
		expectedDetailSnippet string
	}{
		"invalid_syntax": {
			fixture:               "invalid-syntax",
			expectedCode:          "SNYK-OS-PYTHON-0005",
			expectedDetailSnippet: "Invalid syntax in requirements file",
		},
		"nonexistent_package": {
			fixture:               "nonexistent-package",
			expectedCode:          "SNYK-OS-PYTHON-0004",
			expectedDetailSnippet: "Package not found",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "python", tc.fixture)
			absPath, err := filepath.Abs(fixturePath)
			require.NoError(t, err, "failed to get absolute path for fixture")

			plugin := Plugin{}
			results, err := plugin.BuildDepGraphsFromDir(ctx, absPath, ecosystems.NewPluginOptions())
			require.NoError(t, err, "BuildDepGraphsFromDir should not return error")

			require.Len(t, results, 1, "expected a single result for fixture %s", tc.fixture)
			result := results[0]

			// Basic metadata expectations
			assert.Equal(t, "requirements.txt", result.Metadata.TargetFile)
			if pythonVersion != "" {
				assert.Contains(t, result.Metadata.Runtime, fmt.Sprintf("python@%s", pythonVersion))
			}

			assert.Nil(t, result.DepGraph, "dep graph should be nil for pip error fixture %s", tc.fixture)
			require.Error(t, result.Error, "expected an error on the result for fixture %s", tc.fixture)

			var catalogErr snykerrors.Error
			require.True(t, errors.As(result.Error, &catalogErr), "error should be a catalog error")
			assert.Equal(t, tc.expectedCode, catalogErr.ErrorCode)
			assert.Contains(t, catalogErr.Detail, tc.expectedDetailSnippet)
		})
	}
}

// TestPlugin_ContextCancellation tests that context cancellation is respected
func TestPlugin_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	fixturePath := filepath.Join("..", "..", "testdata", "fixtures", "python", "simple")
	absPath, err := filepath.Abs(fixturePath)
	require.NoError(t, err)

	plugin := Plugin{}
	results, err := plugin.BuildDepGraphsFromDir(ctx, absPath, ecosystems.NewPluginOptions())

	// Should handle cancellation gracefully
	if err != nil {
		// If error returned, should be context cancellation
		assert.ErrorIs(t, err, context.Canceled)
	} else {
		// If results returned, they should contain error
		assert.Len(t, results, 1)
		if results[0].Error != nil {
			// Error might be wrapped
			assert.Contains(t, results[0].Error.Error(), "context canceled")
		}
	}
}

// getExpectedOutputPath returns the path to the expected output file
// Tries version-specific file first (e.g., expected_plugin_3.11.json),
// then falls back to expected_plugin.json
func getExpectedOutputPath(t *testing.T, fixturePath, pythonVersion string) string {
	t.Helper()

	// Try version-specific file first (for fixtures like env-markers)
	if pythonVersion != "" {
		versionSpecificPath := filepath.Join(fixturePath, fmt.Sprintf("expected_plugin_%s.json", pythonVersion))
		if _, err := os.Stat(versionSpecificPath); err == nil {
			return versionSpecificPath
		}
	}

	// Fall back to generic file
	genericPath := filepath.Join(fixturePath, "expected_plugin.json")
	if _, err := os.Stat(genericPath); err == nil {
		return genericPath
	}

	return ""
}

// assertResultsMatchExpected compares actual results against exact expected output
func assertResultsMatchExpected(t *testing.T, actual, expected []ecosystems.SCAResult, fixtureName string) {
	t.Helper()

	require.Len(t, actual, len(expected), "[%s] result count mismatch", fixtureName)

	// Sort both by TargetFile for consistent comparison
	sortActual := make([]ecosystems.SCAResult, len(actual))
	copy(sortActual, actual)
	sort.Slice(sortActual, func(i, j int) bool {
		return sortActual[i].Metadata.TargetFile < sortActual[j].Metadata.TargetFile
	})

	sortExpected := make([]ecosystems.SCAResult, len(expected))
	copy(sortExpected, expected)
	sort.Slice(sortExpected, func(i, j int) bool {
		return sortExpected[i].Metadata.TargetFile < sortExpected[j].Metadata.TargetFile
	})

	// Sync runtime field (varies by Python version) and clear Error field (not in JSON)
	for i := range sortExpected {
		sortExpected[i].Metadata.Runtime = sortActual[i].Metadata.Runtime
		sortActual[i].Error = nil // Error field isn't in expected JSON
	}

	// Compare exact structures
	assert.Equal(t, sortExpected, sortActual, "[%s] results mismatch", fixtureName)
}

// loadExpectedResults loads expected SCA results from a JSON file
func loadExpectedResults(path string) ([]ecosystems.SCAResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var expected []ecosystems.SCAResult
	if err := json.Unmarshal(data, &expected); err != nil {
		return nil, err
	}

	return expected, nil
}

// getPythonMajorMinorVersion returns the Python version as "X.Y" (e.g., "3.11")
func getPythonMajorMinorVersion() (string, error) {
	version, err := getPythonVersion()
	if err != nil {
		return "", err
	}

	// Parse version string like "3.11.5" -> "3.11" or "3.14" -> "3.14"
	var major, minor, patch int
	n, err := fmt.Sscanf(version, "%d.%d.%d", &major, &minor, &patch)
	if err != nil && n < 2 {
		return "", fmt.Errorf("failed to parse Python version %s: %w", version, err)
	}

	return fmt.Sprintf("%d.%d", major, minor), nil
}
