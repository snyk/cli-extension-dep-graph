package uvclient_test

import (
	"errors"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/internal/uvclient"
	"github.com/stretchr/testify/assert"
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

	client := uvclient.NewUVClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir")

	assert.NoError(t, err)
	assert.Equal(t, []byte(`{"sbom":"data"}`), result)
}

func TestUVClient_ExportSBOM_Error(t *testing.T) {
	expectedErr := errors.New("command failed")
	mockExecutor := &mockCmdExecutor{
		executeFunc: func(binary, dir string, args ...string) ([]byte, error) {
			return nil, expectedErr
		},
	}

	client := uvclient.NewUVClientWithExecutor("/path/to/uv", mockExecutor)
	result, err := client.ExportSBOM("/test/dir")

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}
