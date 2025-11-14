package uv

import (
	"fmt"
	"os/exec"

	"github.com/rs/zerolog"
)

type Client interface {
	ExportSBOM(inputDir string) ([]byte, error)
	ShouldExportSBOM(inputDir string, logger *zerolog.Logger) bool
}

type uvClient struct {
	uvBinary string
	executor cmdExecutor
}

func NewUvClient() Client {
	return NewUvClientWithPath("uv")
}

func NewUvClientWithPath(uvBinary string) Client {
	return &uvClient{
		uvBinary: uvBinary,
		executor: &defaultCmdExecutor{},
	}
}

// NewUvClientWithExecutor creates a new uv client with a custom executor for testing.
func NewUvClientWithExecutor(uvBinary string, executor cmdExecutor) Client {
	return &uvClient{
		uvBinary: uvBinary,
		executor: executor,
	}
}

// exportSBOM exports an SBOM in CycloneDX format using uv.
func (c *uvClient) ExportSBOM(inputDir string) ([]byte, error) {
	output, err := c.executor.Execute(c.uvBinary, inputDir, "export", "--format", "cyclonedx1.5", "--frozen")
	if err != nil {
		return nil, fmt.Errorf("failed to execute uv export: %w", err)
	}
	return output, nil
}

func (c *uvClient) ShouldExportSBOM(inputDir string, logger *zerolog.Logger) bool {
	return HasUvLockFile(inputDir, logger)
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
