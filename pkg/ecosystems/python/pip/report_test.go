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

func TestClassifyPipError_PrivateIndexAuthHint(t *testing.T) {
	// Realistic pip stderr ends with "No matching distribution" after a private-index
	// 401/403/TLS failure; without the hint users only see "package not found".
	const notFoundTail = "ERROR: Could not find a version that satisfies the requirement private-pkg==1.0.0 (from versions: none)\n" +
		"ERROR: No matching distribution found for private-pkg==1.0.0"

	tests := map[string]struct {
		stderr         string
		wantErrCode    string
		wantHint       bool
		wantDetailPart string // required substring when non-empty (precedence cases)
	}{
		"401_error": {
			stderr: "WARNING: 401 Error, Credentials not correct for https://pypi.example.com/simple/private-pkg/\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		"403_client_error": {
			stderr: "ERROR: 403 Client Error: Forbidden for url: https://pypi.example.com/simple/private-pkg/\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		"client_error_401": {
			stderr: "ERROR: Client Error: 401 for url: https://pypi.example.com/simple/private-pkg/\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		"http_error_403": {
			stderr: "ERROR: HTTP error 403 while getting https://pypi.example.com/simple/private-pkg/\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		"credentials_not_correct": {
			stderr: "WARNING: Credentials not correct for https://pypi.example.com/simple/private-pkg/\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		"unauthorized_for_url": {
			stderr: "ERROR: Unauthorized for url: https://pypi.example.com/simple/private-pkg/\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		"ssl_error": {
			stderr: "ERROR: SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed'))\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		"certificate_verify_failed": {
			stderr: "ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate\n" +
				notFoundTail,
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    true,
		},
		// Bare "401"/"403" appear in versions, ports and URLs; must not trigger the hint.
		"false_positive_bare_401_in_version": {
			stderr: "ERROR: Could not find a version that satisfies the requirement foo==1.401.0 (from versions: 1.400.0, 1.401.0)\n" +
				"ERROR: No matching distribution found for foo==1.401.0 from https://pypi.org:443/simple/foo/",
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    false,
		},
		// Requires-Python classification keeps precedence: auth wording must not turn a
		// version-mismatch failure into package-not-found with an auth hint.
		"requires_python_keeps_precedence": {
			stderr: "WARNING: 401 Error, Credentials not correct for https://pypi.example.com/simple/pkg/\n" +
				"ERROR: Package 'pkg' requires a different Python: 3.9.18 not in '>=3.11'\n" +
				"Requires-Python >=3.11",
			wantErrCode:    "SNYK-OS-PYTHON-0006",
			wantHint:       false,
			wantDetailPart: "Python version mismatch",
		},
		"genuine_missing_package_keeps_plain_message": {
			stderr:      "ERROR: No matching distribution found for nonexistent-package==9.9.9",
			wantErrCode: "SNYK-OS-PYTHON-0004",
			wantHint:    false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := classifyPipError(context.Background(), nil, &pipError{
				err:    fmt.Errorf("exit status 1"),
				stderr: tt.stderr,
			})

			var catalogErr snyk_errors.Error
			require.True(t, errors.As(err, &catalogErr), "should be catalog error")
			assert.Equal(t, tt.wantErrCode, catalogErr.ErrorCode)
			if tt.wantHint {
				assert.Contains(t, catalogErr.Detail, privateIndexAuthHint)
			} else {
				assert.NotContains(t, catalogErr.Detail, privateIndexAuthHint)
			}
			if tt.wantDetailPart != "" {
				assert.Contains(t, catalogErr.Detail, tt.wantDetailPart)
			}
		})
	}
}
