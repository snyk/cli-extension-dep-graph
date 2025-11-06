package uvclient

import (
	"os/exec"
)

type UVClient interface {
	ExportSBOM(inputDir string) ([]byte, error)
}

type uvClient struct {
	uvBinary string
	executor cmdExecutor
}

func NewUVClient() UVClient {
	return NewUVClientWithPath("uv")
}

func NewUVClientWithPath(uvBinary string) UVClient {
	return &uvClient{
		uvBinary: uvBinary,
		executor: &defaultCmdExecutor{},
	}
}

// creates a new UV client with a custom executor for testing
func NewUVClientWithExecutor(uvBinary string, executor cmdExecutor) UVClient {
	return &uvClient{
		uvBinary: uvBinary,
		executor: executor,
	}
}

// ExportSBOM exports an SBOM in CycloneDX format using UV
func (c *uvClient) ExportSBOM(inputDir string) ([]byte, error) {
	return c.executor.Execute(c.uvBinary, inputDir, "export", "--format", "cyclonedx1.5", "--frozen")
}

// cmdExecutor interface for executing commands mockable
type cmdExecutor interface {
	Execute(binary, dir string, args ...string) ([]byte, error)
}

// defaultCmdExecutor is the real implementation of cmdExecutor
type defaultCmdExecutor struct{}

func (e *defaultCmdExecutor) Execute(binary, dir string, args ...string) ([]byte, error) {
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	return cmd.Output()
}
