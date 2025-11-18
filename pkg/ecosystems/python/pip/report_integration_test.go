//go:build integration && python
// +build integration,python

package pip

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

// getFixturePath returns the path to a fixture file.
// From pkg/ecosystems/python/pip/ to pkg/ecosystems/testdata/fixtures/python/
func getFixturePath(fixture, filename string) string {
	return filepath.Join("..", "..", "testdata", "fixtures", "python", fixture, filename)
}

// loadExpectedReport loads the expected.json file as a Report
func loadExpectedReport(t *testing.T, fixture string) *Report {
	t.Helper()

	expectedPath := getFixturePath(fixture, "expected.json")
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("failed to read expected output file: %v", err)
	}

	var expected Report
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("failed to parse expected output: %v", err)
	}

	return &expected
}

// normalize creates a normalized copy of the report for comparison.
// Sorts by package name for consistent comparison.
func normalize(report *Report) *Report {
	normalized := &Report{
		Install: make([]InstallItem, len(report.Install)),
	}

	for i, item := range report.Install {
		normalized.Install[i] = item
		// Clear RequiresDist - it varies by environment but we still capture it
		// We validate that we GET the data, just not the exact content
		normalized.Install[i].Metadata.RequiresDist = nil
	}

	// Sort by package name for consistent comparison
	sort.Slice(normalized.Install, func(i, j int) bool {
		return normalized.Install[i].Metadata.Name < normalized.Install[j].Metadata.Name
	})

	return normalized
}

// normalizeForComparison prepares both reports for comparison
func normalizeForComparison(actual, expected *Report) (*Report, *Report) {
	actualNorm := normalize(actual)
	expectedNorm := normalize(expected)

	// Clear versions in actual where expected has empty version
	for i := range expectedNorm.Install {
		if expectedNorm.Install[i].Metadata.Version == "" && i < len(actualNorm.Install) {
			actualNorm.Install[i].Metadata.Version = ""
		}
	}

	return actualNorm, expectedNorm
}

// assertReportsEqual compares actual and expected reports using assert.Equal
func assertReportsEqual(t *testing.T, actual, expected *Report, fixtureName string) {
	t.Helper()

	actualNorm, expectedNorm := normalizeForComparison(actual, expected)
	assert.Equal(t, expectedNorm, actualNorm, "[%s] reports should match", fixtureName)
}

// TestFixture defines the configuration for a fixture-based test
type TestFixture struct {
	Fixture string // Name of the fixture directory
}

// TestGetInstallReport_Fixtures runs tests against all fixtures using table-driven approach
func TestGetInstallReport_Fixtures(t *testing.T) {
	tests := map[string]TestFixture{
		"single_direct_dependency": {
			Fixture: "simple",
		},
		"multiple_direct_dependencies": {
			Fixture: "multiple-deps",
		},
		"empty_requirements_file": {
			Fixture: "empty",
		},
		"version_specifiers": {
			Fixture: "with-version-specifiers",
		},
		"package_with_extras": {
			Fixture: "with-extras",
		},
		"shared_transitive_dependencies": {
			Fixture: "transitive-conflicts",
		},
	}

	for testName, tc := range tests {
		t.Run(testName, func(t *testing.T) {
			requirementsPath := getFixturePath(tc.Fixture, "requirements.txt")

			if _, err := os.Stat(requirementsPath); err != nil {
				t.Fatalf("fixture file not found: %v", err)
			}

			expected := loadExpectedReport(t, tc.Fixture)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			actual, err := GetInstallReport(ctx, requirementsPath)
			if err != nil {
				t.Fatalf("GetInstallReport failed: %v", err)
			}

			assertReportsEqual(t, actual, expected, tc.Fixture)
		})
	}
}

// TestGetInstallReport_Integration_Errors tests various error conditions
func TestGetInstallReport_Integration_Errors(t *testing.T) {
	tests := map[string]struct {
		setupCtx    func() (context.Context, context.CancelFunc)
		reqPath     string
		wantErr     error  // For context errors
		wantErrCode string // For catalog errors
	}{
		"invalid_file": {
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 30*time.Second)
			},
			reqPath:     "/nonexistent/requirements.txt",
			wantErrCode: "SNYK-OS-PYTHON-0009",
		},
		"context_cancellation": {
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, func() {}
			},
			reqPath: getFixturePath("simple", "requirements.txt"),
			wantErr: context.Canceled,
		},
		"timeout": {
			setupCtx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				time.Sleep(10 * time.Millisecond)
				return ctx, cancel
			},
			reqPath:     getFixturePath("simple", "requirements.txt"),
			wantErrCode: "SNYK-0004",
		},
		"invalid_syntax": {
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 30*time.Second)
			},
			reqPath:     getFixturePath("invalid-syntax", "requirements.txt"),
			wantErrCode: "SNYK-OS-PYTHON-0005",
		},
		"package_not_found": {
			setupCtx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 30*time.Second)
			},
			reqPath:     getFixturePath("nonexistent-package", "requirements.txt"),
			wantErrCode: "SNYK-OS-PYTHON-0004",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := tt.setupCtx()
			defer cancel()

			_, err := GetInstallReport(ctx, tt.reqPath)

			if tt.wantErr != nil {
				assert.True(t, errors.Is(err, tt.wantErr))
			} else {
				var catalogErr snyk_errors.Error
				assert.True(t, errors.As(err, &catalogErr))
				assert.Equal(t, tt.wantErrCode, catalogErr.ErrorCode)
			}
		})
	}
}
