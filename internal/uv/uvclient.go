package uv

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/rs/zerolog"
)

type Client interface {
	ExportSBOM(inputDir string) ([]byte, error)
	ShouldExportSBOM(inputDir string, logger *zerolog.Logger) bool
}

type client struct {
	uvBinary string
	executor cmdExecutor
}

var _ Client = (*client)(nil)

func NewUvClient() Client {
	return NewUvClientWithPath("uv")
}

func NewUvClientWithPath(uvBinary string) Client {
	return NewUvClientWithExecutor(uvBinary, &defaultCmdExecutor{})
}

// NewUvClientWithExecutor creates a new uv client with a custom executor for testing.
func NewUvClientWithExecutor(uvBinary string, executor cmdExecutor) Client {
	return &client{
		uvBinary: uvBinary,
		executor: executor,
	}
}

// exportSBOM exports an SBOM in CycloneDX format using uv.
func (c client) ExportSBOM(inputDir string) ([]byte, error) {
	output, err := c.executor.Execute(c.uvBinary, inputDir, "export", "--format", "cyclonedx1.5", "--frozen", "--preview")
	if err != nil {
		return nil, fmt.Errorf("failed to execute uv export: %w", err)
	}
	return output, nil
}

func (c *client) ShouldExportSBOM(inputDir string, logger *zerolog.Logger) bool {
	return HasUvLockFile(inputDir, logger)
}

// cmdExecutor interface for executing commands mockable.
type cmdExecutor interface {
	Execute(binary, dir string, args ...string) ([]byte, error)
}

// defaultCmdExecutor is the real implementation of cmdExecutor.
type defaultCmdExecutor struct{}

func (e *defaultCmdExecutor) Execute(binary, dir string, args ...string) ([]byte, error) {
	// Check if uv binary exists in PATH
	_, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("%s binary not found in PATH", binary)
	}

	//nolint:govet // Reassigning to err is fine
	if err := checkVersion(binary); err != nil {
		return nil, err
	}

	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w\noutput: %s", err, output)
	}
	return output, nil
}

func checkVersion(binary string) error {
	cmd := exec.Command(binary, "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get %s version: %w\noutput: %s", binary, err, output)
	}
	return parseAndValidateVersion(binary, string(output))
}

func parseAndValidateVersion(binary, versionOutput string) error {
	versionRe := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	matches := versionRe.FindStringSubmatch(versionOutput)
	// First element in matches is the full match, remainder are capture groups
	if len(matches) < 4 {
		return fmt.Errorf("unable to parse %s version from output: %s", binary, versionOutput)
	}

	curVersion := Version{
		mustAtoi(matches[1]),
		mustAtoi(matches[2]),
		mustAtoi(matches[3]),
	}
	minVersion := Version{0, 9, 10} // Min version containing SBOM export functionality
	if compareVersions(curVersion, minVersion) >= 0 {
		return nil
	}

	return fmt.Errorf("%s version %d.%d.%d is not supported. Minimum required version is 0.9.10", binary, curVersion[0], curVersion[1], curVersion[2])
}

type Version = [3]int

// Compares two semantic versions.
// Returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
func compareVersions(v1, v2 Version) int {
	for i := range len(v1) {
		if v1[i] < v2[i] {
			return -1
		}
		if v1[i] > v2[i] {
			return 1
		}
	}
	return 0
}

func mustAtoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("failed to convert %q to int: %v", s, err))
	}
	return i
}
