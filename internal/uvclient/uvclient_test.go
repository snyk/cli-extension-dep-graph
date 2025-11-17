package uvclient

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	mockExecutor := &mockCmdExecutor{
		executeFunc: func(binary, dir string, args ...string) ([]byte, error) {
			assert.Equal(t, "/path/to/uv", binary)
			assert.Equal(t, "/test/dir", dir)
			assert.Equal(t, []string{"export", "--format", "cyclonedx1.5", "--frozen"}, args)
			return []byte(`{"sbom":"data"}`), nil
		},
	}

	client := NewUVClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir")

	assert.NoError(t, err)
	assert.Equal(t, []byte(`{"sbom":"data"}`), result)
}

func TestUVClient_ExportSBOM_Error(t *testing.T) {
	expectedErr := errors.New("command failed")
	mockExecutor := &mockCmdExecutor{
		executeFunc: func(_, _ string, _ ...string) ([]byte, error) {
			return nil, expectedErr
		},
	}

	client := NewUVClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir")

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
	assert.Nil(t, result)
}

func TestParseAndValidateVersion_ValidVersions(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"exact minimum", "uv 0.9.10"},
		{"patch higher", "uv 0.9.11"},
		{"minor higher", "uv 0.10.0"},
		{"major higher", "uv 1.0.0"},
		{"with commit hash", "uv 0.9.10 (982851bf9)"},
		{"with commit hash and suffix", "uv 0.9.10+43 (982851bf9 2025-11-13)"},
		{"without prefix", "0.9.10"},
		{"future version", "uv 2.5.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseAndValidateVersion("uv", tt.output)
			assert.NoError(t, err)
		})
	}
}

func TestParseAndValidateVersion_InvalidVersions(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"patch too low", "uv 0.9.9"},
		{"minor too low", "uv 0.8.21"},
		{"major and minor both 0", "uv 0.0.1"},
		{"minor too low with commit hash", "uv 0.9.9 (982851bf9)"},
		{"minor too low with commit hash and suffix", "uv 0.9.9+43 (982851bf9 2025-11-13)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseAndValidateVersion("uv", tt.output)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not supported")
			assert.Contains(t, err.Error(), "0.9.10")
		})
	}
}

func TestParseAndValidateVersion_UnparseableOutput(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{"no version", "uv command not found"},
		{"invalid format", "version: abc"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseAndValidateVersion("uv", tt.output)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unable to parse")
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       Version
		v2       Version
		expected int
	}{
		{"equal versions", Version{1, 2, 3}, Version{1, 2, 3}, 0},
		{"v1 less than v2 major", Version{0, 2, 3}, Version{1, 2, 3}, -1},
		{"v1 less than v2 minor", Version{1, 1, 3}, Version{1, 2, 3}, -1},
		{"v1 less than v2 patch", Version{1, 2, 2}, Version{1, 2, 3}, -1},
		{"v1 greater than v2 major", Version{2, 0, 0}, Version{1, 9, 9}, 1},
		{"v1 greater than v2 minor", Version{1, 3, 0}, Version{1, 2, 9}, 1},
		{"v1 greater than v2 patch", Version{1, 2, 4}, Version{1, 2, 3}, 1},
		{"exact minimum check", Version{0, 9, 10}, Version{0, 9, 10}, 0},
		{"one below minimum", Version{0, 9, 9}, Version{0, 9, 10}, -1},
		{"one above minimum", Version{0, 9, 11}, Version{0, 9, 10}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersions(tt.v1, tt.v2)
			assert.Equal(t, tt.expected, result)
		})
	}
}
