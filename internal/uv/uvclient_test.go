package uv

import (
	"errors"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
)

type mockCmdExecutor struct {
	executeFunc func(binary, dir string, args ...string) ([]byte, error)
}

func (m *mockCmdExecutor) Execute(binary, dir string, args ...string) ([]byte, error) {
	if m.executeFunc != nil {
		return m.executeFunc(binary, dir, args...)
	}
	return []byte(`{"mock":"sbom"}`), nil
}

func TestUVClient_ExportSBOM_Success(t *testing.T) {
	validSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"type": "library",
				"bom-ref": "test-project-1",
				"name": "test-project",
				"version": "1.2.3"
			}
		}
	}`

	mockExecutor := &mockCmdExecutor{
		executeFunc: func(binary, dir string, args ...string) ([]byte, error) {
			assert.Equal(t, "/path/to/uv", binary)
			assert.Equal(t, "/test/dir", dir)
			assert.Equal(t, []string{"export", "--format", "cyclonedx1.5", "--locked", "--preview", "--no-dev"}, args)
			return []byte(validSBOM), nil
		},
	}

	client := NewUvClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir", &scaplugin.Options{})

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.JSONEq(t, validSBOM, string(result))
}

func TestUVClient_ExportSBOM_AllProjects(t *testing.T) {
	validSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"type": "library",
				"bom-ref": "test-project-1",
				"name": "test-project",
				"version": "1.2.3"
			}
		}
	}`

	mockExecutor := &mockCmdExecutor{
		executeFunc: func(binary, dir string, args ...string) ([]byte, error) {
			assert.Equal(t, "/path/to/uv", binary)
			assert.Equal(t, "/test/dir", dir)
			assert.Equal(t, []string{"export", "--format", "cyclonedx1.5", "--locked", "--preview", "--all-packages", "--no-dev"}, args)
			return []byte(validSBOM), nil
		},
	}

	client := NewUvClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir", &scaplugin.Options{
		AllProjects:         true,
		UvWorkspacePackages: false,
	})

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.JSONEq(t, validSBOM, string(result))
}

func TestUVClient_ExportSBOM_UvWorkspacePackages(t *testing.T) {
	validSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"component": {
				"type": "library",
				"bom-ref": "test-project-1",
				"name": "test-project",
				"version": "1.2.3"
			}
		}
	}`

	mockExecutor := &mockCmdExecutor{
		executeFunc: func(binary, dir string, args ...string) ([]byte, error) {
			assert.Equal(t, "/path/to/uv", binary)
			assert.Equal(t, "/test/dir", dir)
			assert.Equal(t, []string{"export", "--format", "cyclonedx1.5", "--locked", "--preview", "--all-packages", "--no-dev"}, args)
			return []byte(validSBOM), nil
		},
	}

	client := NewUvClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir", &scaplugin.Options{
		AllProjects:         false,
		UvWorkspacePackages: true,
	})

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.JSONEq(t, validSBOM, string(result))
}

func TestUVClient_ExportSBOM_DevTrue_OmitsNoDevFlag(t *testing.T) {
	validSBOM := `{"metadata": {"component": {"name": "test", "version": "1.0.0"}}}`

	mockExecutor := &mockCmdExecutor{
		executeFunc: func(_, _ string, args ...string) ([]byte, error) {
			for _, arg := range args {
				assert.NotEqual(t, "--no-dev", arg, "args should not contain --no-dev when Dev is true")
			}
			return []byte(validSBOM), nil
		},
	}

	client := NewUvClientWithExecutor("/path/to/uv", mockExecutor)
	_, err := client.ExportSBOM("/test/dir", &scaplugin.Options{Dev: true})

	assert.NoError(t, err)
}

func TestUVClient_ExportSBOM_Error(t *testing.T) {
	expectedErr := errors.New("command failed")
	mockExecutor := &mockCmdExecutor{
		executeFunc: func(_, _ string, _ ...string) ([]byte, error) {
			return nil, expectedErr
		},
	}

	client := NewUvClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir", &scaplugin.Options{})

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
	assert.Nil(t, result)
}

func TestUVClient_ExportSBOM_InvalidSBOM(t *testing.T) {
	// ExportSBOM no longer validates SBOMs - validation happens in buildFindings
	// This test verifies that ExportSBOM returns invalid SBOM without error
	invalidSBOM := `{
		"bomFormat": "CycloneDX",
		"metadata": {}
	}`

	mockExecutor := &mockCmdExecutor{
		executeFunc: func(_, _ string, _ ...string) ([]byte, error) {
			return []byte(invalidSBOM), nil
		},
	}

	client := NewUvClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir", &scaplugin.Options{})

	// ExportSBOM should succeed - validation happens later in buildFindings
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.JSONEq(t, invalidSBOM, string(result))
}

func TestExtractMetadata_Success(t *testing.T) {
	tests := []struct {
		name            string
		sbom            string
		expectedName    string
		expectedVersion string
	}{
		{
			name: "valid SBOM with full component",
			sbom: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"metadata": {
					"component": {
						"type": "library",
						"name": "test-project",
						"version": "1.0.0",
						"bom-ref": "test-project-1"
					}
				}
			}`,
			expectedName:    "test-project",
			expectedVersion: "1.0.0",
		},
		{
			name: "valid SBOM with minimal component",
			sbom: `{
				"metadata": {
					"component": {
						"name": "my-project",
						"version": "0.1.0"
					}
				}
			}`,
			expectedName:    "my-project",
			expectedVersion: "0.1.0",
		},
		{
			name: "component without version",
			sbom: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"metadata": {
					"component": {
						"name": "project-no-version"
					}
				}
			}`,
			expectedName:    "project-no-version",
			expectedVersion: "",
		},
		{
			name: "component with empty version string",
			sbom: `{
				"metadata": {
					"component": {
						"name": "project-empty-version",
						"version": ""
					}
				}
			}`,
			expectedName:    "project-empty-version",
			expectedVersion: "",
		},
		{
			name: "component with additional fields",
			sbom: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"metadata": {
					"component": {
						"type": "application",
						"name": "complex-project",
						"version": "3.0.0",
						"bom-ref": "pkg:pypi/complex-project@3.0.0",
						"description": "A complex project",
						"licenses": []
					}
				}
			}`,
			expectedName:    "complex-project",
			expectedVersion: "3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, err := parseAndValidateSBOM([]byte(tt.sbom))
			require.NoError(t, err)
			require.NotNil(t, sbom)

			metadata := extractMetadata(sbom)
			assert.Equal(t, "pip", metadata.PackageManager)
			assert.Equal(t, tt.expectedName, metadata.Name)
			assert.Equal(t, tt.expectedVersion, metadata.Version)
		})
	}
}

func TestExtractMetadata_MissingComponent(t *testing.T) {
	tests := []struct {
		name               string
		sbom               string
		expectedErrMessage string
	}{
		{
			name: "missing component field",
			sbom: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"metadata": {
					"timestamp": "2025-11-17T16:20:47.525804000Z"
				}
			}`,
			expectedErrMessage: "SBOM missing root component at metadata.component",
		},
		{
			name: "missing metadata",
			sbom: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5"
			}`,
			expectedErrMessage: "SBOM missing root component at metadata.component",
		},
		{
			name: "component with empty name",
			sbom: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"metadata": {
					"component": {
						"name": "",
						"version": "1.0.0"
					}
				}
			}`,
			expectedErrMessage: "SBOM root component missing name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, err := parseAndValidateSBOM([]byte(tt.sbom))
			assert.Nil(t, sbom)
			require.Error(t, err)
			var catalogErr snyk_errors.Error
			assert.True(t, errors.As(err, &catalogErr), "error should be a catalog error")
			assert.Contains(t, catalogErr.Detail, tt.expectedErrMessage)
		})
	}
}

func TestExtractMetadata_InvalidJSON(t *testing.T) {
	tests := []struct {
		name           string
		sbom           string
		expectedErrMsg string
	}{
		{
			name:           "invalid json",
			sbom:           "invalid json",
			expectedErrMsg: "Failed to parse SBOM JSON",
		},
		{
			name:           "malformed json - missing closing brace",
			sbom:           `{"metadata": {`,
			expectedErrMsg: "Failed to parse SBOM JSON",
		},
		{
			name:           "null",
			sbom:           "null",
			expectedErrMsg: "SBOM missing root component",
		},
		{
			name:           "empty object",
			sbom:           "{}",
			expectedErrMsg: "SBOM missing root component",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, err := parseAndValidateSBOM([]byte(tt.sbom))
			assert.Nil(t, sbom)
			require.Error(t, err)
			var catalogErr snyk_errors.Error
			assert.True(t, errors.As(err, &catalogErr), "error should be a catalog error")
			assert.Contains(t, catalogErr.Detail, tt.expectedErrMsg)
		})
	}
}

func TestExtractWorkspacePackages(t *testing.T) {
	tests := []struct {
		name     string
		sbom     string
		expected []WorkspacePackage
	}{
		{
			name: "single workspace package",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "lib-core",
						"version": "0.1.0",
						"properties": [
							{"name": "uv:workspace:path", "value": "packages/lib-core"}
						]
					}
				]
			}`,
			expected: []WorkspacePackage{
				{Name: "lib-core", Version: "0.1.0", Path: "packages/lib-core"},
			},
		},
		{
			name: "multiple workspace packages",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "lib-core",
						"version": "0.1.0",
						"properties": [
							{"name": "uv:workspace:path", "value": "packages/lib-core"}
						]
					},
					{
						"name": "lib-utils",
						"version": "0.2.0",
						"properties": [
							{"name": "uv:workspace:path", "value": "packages/lib-utils"}
						]
					}
				]
			}`,
			expected: []WorkspacePackage{
				{Name: "lib-core", Version: "0.1.0", Path: "packages/lib-core"},
				{Name: "lib-utils", Version: "0.2.0", Path: "packages/lib-utils"},
			},
		},
		{
			name: "mixed workspace and regular packages",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "requests",
						"version": "2.31.0",
						"purl": "pkg:pypi/requests@2.31.0"
					},
					{
						"name": "lib-core",
						"version": "0.1.0",
						"properties": [
							{"name": "uv:workspace:path", "value": "packages/lib-core"}
						]
					},
					{
						"name": "pydantic",
						"version": "2.5.0",
						"purl": "pkg:pypi/pydantic@2.5.0"
					}
				]
			}`,
			expected: []WorkspacePackage{
				{Name: "lib-core", Version: "0.1.0", Path: "packages/lib-core"},
			},
		},
		{
			name: "component with other properties but not workspace path",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "colorama",
						"version": "0.4.6",
						"properties": [
							{"name": "uv:package:marker", "value": "sys_platform == 'win32'"}
						]
					}
				]
			}`,
			expected: nil,
		},
		{
			name: "component with multiple properties including workspace path",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "lib-core",
						"version": "0.1.0",
						"properties": [
							{"name": "some:other:property", "value": "some-value"},
							{"name": "uv:workspace:path", "value": "packages/lib-core"},
							{"name": "another:property", "value": "another-value"}
						]
					}
				]
			}`,
			expected: []WorkspacePackage{
				{Name: "lib-core", Version: "0.1.0", Path: "packages/lib-core"},
			},
		},
		{
			name: "no components",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": []
			}`,
			expected: nil,
		},
		{
			name: "sbom without components field",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				}
			}`,
			expected: nil,
		},
		{
			name: "component with empty properties array",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "some-package",
						"version": "1.0.0",
						"properties": []
					}
				]
			}`,
			expected: nil,
		},
		{
			name: "component with workspace path but empty value",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "lib-core",
						"version": "0.1.0",
						"properties": [
							{"name": "uv:workspace:path", "value": ""}
						]
					}
				]
			}`,
			expected: []WorkspacePackage{
				{Name: "lib-core", Version: "0.1.0", Path: ""},
			},
		},
		{
			name: "component with nil properties (missing field)",
			sbom: `{
				"metadata": {
					"component": {
						"name": "test-project",
						"version": "1.0.0"
					}
				},
				"components": [
					{
						"name": "some-package",
						"version": "1.0.0"
					}
				]
			}`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, err := parseAndValidateSBOM([]byte(tt.sbom))
			require.NoError(t, err)
			require.NotNil(t, sbom)

			result := extractWorkspacePackages(sbom)
			assert.Equal(t, tt.expected, result)
		})
	}
}
