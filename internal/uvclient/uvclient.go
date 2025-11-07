package uvclient

import (
	"fmt"
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

// NewUVClientWithExecutor creates a new UV client with a custom executor for testing.
func NewUVClientWithExecutor(uvBinary string, executor cmdExecutor) UVClient {
	return &uvClient{
		uvBinary: uvBinary,
		executor: executor,
	}
}

// ExportSBOM exports an SBOM in CycloneDX format using UV.
func (c *uvClient) ExportSBOM(inputDir string) ([]byte, error) {
	output, err := c.executor.Execute(c.uvBinary, inputDir, "export", "--format", "cyclonedx1.5", "--frozen")
	if err != nil {
		return nil, fmt.Errorf("failed to execute uv export: %w", err)
	}
	return output, nil
}

// cmdExecutor interface for executing commands mockable.
type cmdExecutor interface {
	Execute(binary, dir string, args ...string) ([]byte, error)
}

// defaultCmdExecutor is the real implementation of cmdExecutor.
type defaultCmdExecutor struct{}

func (e *defaultCmdExecutor) Execute(binary, dir string, args ...string) ([]byte, error) {
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	return output, nil
}
