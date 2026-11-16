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
		wantAuthHint   bool
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
		"index_auth_warning_then_no_matching_distribution": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "WARNING: 401 Error, Credentials not correct for https://pypi.example.com/simple/internal-lib/\n" +
					"ERROR: Could not find a version that satisfies the requirement internal-lib==1.2.3 (from versions: none)\n" +
					"ERROR: No matching distribution found for internal-lib==1.2.3",
			},
			wantErrCode:  "SNYK-OS-PYTHON-0004",
			wantAuthHint: true,
		},
		"index_403_client_error": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "WARNING: Skipping page https://pypi.example.com/simple/internal-lib/ because the GET request got Content-Type: text/html\n" +
					"Could not fetch URL https://pypi.example.com/simple/internal-lib/: 403 Client Error: Forbidden for url: https://pypi.example.com/simple/internal-lib/ - skipping\n" +
					"ERROR: No matching distribution found for internal-lib",
			},
			wantErrCode:  "SNYK-OS-PYTHON-0004",
			wantAuthHint: true,
		},
		"index_http_error_401": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "ERROR: HTTP error 401 while getting https://pypi.example.com/packages/internal-lib-1.2.3.tar.gz\n" +
					"ERROR: Could not install requirement internal-lib==1.2.3\n" +
					"ERROR: No matching distribution found for internal-lib==1.2.3",
			},
			wantErrCode:  "SNYK-OS-PYTHON-0004",
			wantAuthHint: true,
		},
		"index_client_error_401_unauthorized": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "Could not fetch URL https://pypi.example.com/simple/x/: 401 Client Error: Unauthorized for url: https://pypi.example.com/simple/x/\n" +
					"ERROR: No matching distribution found for x",
			},
			wantErrCode:  "SNYK-OS-PYTHON-0004",
			wantAuthHint: true,
		},
		"index_ssl_error": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "WARNING: Retrying (Retry(total=0)) after connection broken by 'SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed'))': /simple/x/\n" +
					"ERROR: Could not find a version that satisfies the requirement x (from versions: none)\n" +
					"ERROR: No matching distribution found for x",
			},
			wantErrCode:  "SNYK-OS-PYTHON-0004",
			wantAuthHint: true,
		},
		"version_and_url_numbers_do_not_trigger_auth_hint": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "ERROR: Could not find a version that satisfies the requirement foo==4.0.1 (from versions: 1.0, 4.03)\n" +
					"ERROR: No matching distribution found for foo==4.0.1\n" +
					"Looking in indexes: https://pypi.org/simple, https://host:4013/simple",
			},
			wantErrCode: "SNYK-OS-PYTHON-0004",
		},
		"requires_python_still_wins_over_auth_hint": {
			err: &pipError{
				err: fmt.Errorf("exit status 1"),
				stderr: "WARNING: 401 Error, Credentials not correct for https://other.example.com/simple/dnspython/\n" +
					"ERROR: Ignored the following versions that require a different python version: 2.9.0 Requires-Python >=3.11\n" +
					"ERROR: Could not find a version that satisfies the requirement dnspython==2.9.0 (from versions: 2.8.0)\n" +
					"ERROR: No matching distribution found for dnspython==2.9.0",
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
				if tt.wantAuthHint {
					assert.Contains(t, catalogErr.Detail, pipIndexAuthHint)
				} else {
					assert.NotContains(t, catalogErr.Detail, pipIndexAuthHint)
				}
			} else {
				// Should be a generic error
				assert.Contains(t, err.Error(), "pip install failed")
			}
		})
	}
}
