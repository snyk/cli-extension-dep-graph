package pip

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

// MockExecutor is a test implementation of CommandExecutor.
type MockExecutor struct {
	Output []byte
	Err    error
}

func (m *MockExecutor) Execute(_ context.Context, _ string, _ ...string) ([]byte, error) {
	return m.Output, m.Err
}

func TestGetInstallReportWithExecutor_EmptyRequirementsFile(t *testing.T) {
	executor := &MockExecutor{}
	ctx := context.Background()

	_, err := GetInstallReportWithExecutor(ctx, "", executor)

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
	_, err := GetInstallReportWithExecutor(ctx, "requirements.txt", executor)

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
				stderr: "ERROR: Invalid requirement: 'invalid===syntax!!!'",
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
			wantErrCode: "SNYK-0004",
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
			err := classifyPipError(tt.err)

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
