//go:build !integration
// +build !integration

package pip

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockExecutor is a test implementation of CommandExecutor.
type MockExecutor struct {
	Output []byte
	Err    error
}

func (m *MockExecutor) Execute(_ context.Context, _, _ string, _ ...string) ([]byte, error) {
	return m.Output, m.Err
}

func TestGetInstallReportWithExecutor_EmptyRequirementsFile(t *testing.T) {
	executor := &MockExecutor{}
	ctx := context.Background()

	_, err := GetInstallReportWithExecutor(ctx, nil, "", false, executor)

	if err == nil {
		t.Fatal("expected error for empty requirements file")
	}

	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGetInstallReportWithExecutor_InvalidJSON(t *testing.T) {
	executor := &MockExecutor{
		Output: []byte("not valid json"),
		Err:    nil,
	}

	ctx := context.Background()
	_, err := GetInstallReportWithExecutor(ctx, nil, "requirements.txt", false, executor)

	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}

	if !strings.Contains(err.Error(), "failed to parse pip report") {
		t.Errorf("expected error to mention parse failure, got: %v", err)
	}
}

func TestClassifyPipError(t *testing.T) {
	tests := map[string]struct {
		err            error
		wantErrCode    string
		wantContextErr error
	}{
		"syntax_error_invalid_requirement": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: Invalid requirement: 'invalid-syntax['",
			},
			wantErrCode: "SNYK-OS-PYTHON-0005",
		},
		"syntax_error_invalid_version": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "pip._vendor.packaging.version.InvalidVersion: Invalid version: 'bad'",
			},
			wantErrCode: "SNYK-OS-PYTHON-0005",
		},
		"syntax_error_could_not_parse": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: Could not parse requirement",
			},
			wantErrCode: "SNYK-OS-PYTHON-0005",
		},
		"package_not_found": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: Could not find a version that satisfies the requirement nonexistent-package",
			},
			wantErrCode: "SNYK-OS-PYTHON-0004",
		},
		"no_matching_distribution": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: No matching distribution found for some-package",
			},
			wantErrCode: "SNYK-OS-PYTHON-0004",
		},
		"python_version_mismatch": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: Package requires Python >=3.10 but you have 3.9",
			},
			wantErrCode: "SNYK-OS-PYTHON-0006",
		},
		"requires_python": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: Requires-Python: >=3.11",
			},
			wantErrCode: "SNYK-OS-PYTHON-0006",
		},
		"requires_python_takes_precedence_over_no_matching_distribution": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "ERROR: Ignored the following versions that require a different python version: " +
					"2.9.0 Requires-Python >=3.11\n" +
					"ERROR: Could not find a version that satisfies the requirement dnspython==2.9.0 (from versions: 1.16.0, 2.8.0)\n" +
					"ERROR: No matching distribution found for dnspython==2.9.0",
			},
			wantErrCode: "SNYK-OS-PYTHON-0006",
		},
		"unrelated_requires_python_line_does_not_hide_package_not_found": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "ERROR: Ignored the following versions that require a different python version: " +
					"2.32.5 Requires-Python >=3.9; 2.33.0 Requires-Python >=3.10\n" +
					"ERROR: Could not find a version that satisfies the requirement this-package-does-not-exist==1.0.0 (from versions: none)\n" +
					"ERROR: No matching distribution found for this-package-does-not-exist==1.0.0",
			},
			wantErrCode: "SNYK-OS-PYTHON-0004",
		},
		"conflicting_requirements": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: Conflicting requirements: package1 requires foo>=2.0, package2 requires foo<2.0",
			},
			wantErrCode: "SNYK-OS-PYTHON-0007",
		},
		"incompatible_packages": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "ERROR: packages are incompatible",
			},
			wantErrCode: "SNYK-OS-PYTHON-0007",
		},
		"context_canceled": {
			err: &pipError{
				err:    context.Canceled,
				stderr: "",
			},
			wantContextErr: context.Canceled,
		},
		"context_deadline_exceeded": {
			err: &pipError{
				err:    context.DeadlineExceeded,
				stderr: "some output",
			},
			wantErrCode: "SNYK-OS-PYTHON-0009",
		},
		"generic_pip_error": {
			err: &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: "Some other pip error",
			},
			wantErrCode: "SNYK-OS-PYTHON-0009",
		},
		"non_pip_error": {
			err:         fmt.Errorf("some other error"),
			wantErrCode: "", // Should return generic error, not catalog error
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if errors.Is(tt.err, context.Canceled) {
				cancel()
			} else {
				defer cancel()
			}
			err := classifyPipError(ctx, nil, tt.err)

			// Check for context error
			if tt.wantContextErr != nil {
				assert.True(t, errors.Is(err, tt.wantContextErr))
				return
			}

			// Check for catalog error
			if tt.wantErrCode != "" {
				var catalogErr snyk_errors.Error
				assert.True(t, errors.As(err, &catalogErr), "should be catalog error")
				assert.Equal(t, tt.wantErrCode, catalogErr.ErrorCode)
			} else {
				// Should be a generic error
				assert.Contains(t, err.Error(), "pip install failed")
			}
		})
	}
}

const pinnedNeedsNewerPythonStderr = "ERROR: Ignored the following versions that require a different python version: " +
	"2.9.0 Requires-Python >=3.11\n" +
	"ERROR: Could not find a version that satisfies the requirement dnspython==2.9.0 (from versions: 1.16.0, 2.8.0)\n" +
	"ERROR: No matching distribution found for dnspython==2.9.0"

func TestClassifyPipError_UnsupportedPythonVersionNamesInterpreter(t *testing.T) {
	err := classifyPipError(context.Background(), nil, &pipError{
		err:           fmt.Errorf("exit status 1"),
		stderr:        pinnedNeedsNewerPythonStderr,
		pythonVersion: "3.9.18",
	})

	var catalogErr snyk_errors.Error
	require.True(t, errors.As(err, &catalogErr))
	assert.Equal(t, "SNYK-OS-PYTHON-0006", catalogErr.ErrorCode)
	assert.Contains(t, catalogErr.Detail, "dnspython 2.9.0 requires Python >=3.11, but this scan used Python 3.9.18.")
	// The extension serves both the CLI and SCM scans, so both remedies must be given.
	assert.Contains(t, catalogErr.Detail, "Snyk CLI: put a compatible interpreter first on your PATH")
	assert.Contains(t, catalogErr.Detail, "SCM integration: set the Python version in your project's .snyk file")
	assert.Contains(t, catalogErr.Detail, pinnedNeedsNewerPythonStderr)
}

func TestClassifyPipError_UnsupportedPythonVersionWithoutKnownInterpreter(t *testing.T) {
	err := classifyPipError(context.Background(), nil, &pipError{
		err:    fmt.Errorf("exit status 1"),
		stderr: pinnedNeedsNewerPythonStderr,
	})

	var catalogErr snyk_errors.Error
	require.True(t, errors.As(err, &catalogErr))
	assert.Equal(t, "SNYK-OS-PYTHON-0006", catalogErr.ErrorCode)
	assert.Contains(t, catalogErr.Detail, "dnspython 2.9.0 requires Python >=3.11, which is different from the Python used for this scan.")
	assert.NotContains(t, catalogErr.Detail, "Python  ")
	assert.Contains(t, catalogErr.Detail, "SCM integration:")
}

func TestClassifyPipError_UnsupportedPythonVersionGenericRequiresPython(t *testing.T) {
	// A bare Requires-Python line with no matching pin still reaches the generic branch.
	err := classifyPipError(context.Background(), nil, &pipError{
		err:           fmt.Errorf("exit status 1"),
		stderr:        "ERROR: Package 'foo' requires a different Python: 3.9.18 not in '>=3.11'\nRequires-Python >=3.11",
		pythonVersion: "3.9.18",
	})

	var catalogErr snyk_errors.Error
	require.True(t, errors.As(err, &catalogErr))
	assert.Equal(t, "SNYK-OS-PYTHON-0006", catalogErr.ErrorCode)
	assert.Contains(t, catalogErr.Detail, "needs a different Python version than the one used for this scan (Python 3.9.18).")
	assert.Contains(t, catalogErr.Detail, "Snyk CLI:")
	assert.Contains(t, catalogErr.Detail, "SCM integration:")
}

func TestRunPipInstall_AttachesPythonVersionToPipError(t *testing.T) {
	orig := detectPythonVersion
	detectPythonVersion = func() (string, error) { return "3.9.18", nil }
	t.Cleanup(func() { detectPythonVersion = orig })

	executor := &MockExecutor{Err: &pipError{err: fmt.Errorf("exit status 1"), stderr: pinnedNeedsNewerPythonStderr}}
	_, err := GetInstallReportWithExecutor(context.Background(), nil, "requirements.txt", false, executor)

	var catalogErr snyk_errors.Error
	require.True(t, errors.As(err, &catalogErr))
	assert.Contains(t, catalogErr.Detail, "Python 3.9.18")
}

func TestRunPipInstall_DoesNotDetectPythonForOtherErrors(t *testing.T) {
	orig := detectPythonVersion
	detectPythonVersion = func() (string, error) { t.Fatal("should not be called"); return "", nil }
	t.Cleanup(func() { detectPythonVersion = orig })

	executor := &MockExecutor{Err: &pipError{err: fmt.Errorf("exit status 1"), stderr: "ERROR: No matching distribution found for nope==1"}}
	_, err := GetInstallReportWithExecutor(context.Background(), nil, "requirements.txt", false, executor)
	require.Error(t, err)
}
