package uv

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	clierrors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

var minVersion = Version{0, 9, 23}

// cmdExecutor interface for executing commands mockable.
type cmdExecutor interface {
	Execute(binary, dir string, args ...string) ([]byte, error)
}

// uvCmdExecutor is the cmdExecutor implementation for the uv command, handling its execution and output capture.
type uvCmdExecutor struct{}

func (e *uvCmdExecutor) Execute(binary, dir string, args ...string) ([]byte, error) {
	// Check if uv binary exists in PATH and resolve the full path
	resolvedBinary, err := exec.LookPath(binary)
	if err != nil {
		return nil, clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("%s binary not found in PATH", binary),
			snyk_errors.WithCause(err),
		)
	}

	//nolint:govet // Reassigning to err is fine
	if err := checkVersion(resolvedBinary); err != nil {
		return nil, err
	}

	cmd := exec.Command(resolvedBinary, args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return nil, clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("failed to execute uv export command: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String()),
			snyk_errors.WithCause(err),
		)
	}
	return stdout.Bytes(), nil
}

func checkVersion(binary string) error {
	cmd := exec.Command(binary, "--version")
	output, err := cmd.Output()
	if err != nil {
		return clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("failed to get %s version\noutput: %s", binary, string(output)),
			snyk_errors.WithCause(err),
		)
	}
	return parseAndValidateVersion(binary, string(output))
}

func parseAndValidateVersion(binary, versionOutput string) error {
	versionRe := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	matches := versionRe.FindStringSubmatch(versionOutput)
	// First element in matches is the full match, remainder are capture groups
	if len(matches) < 4 {
		return clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("unable to parse %s version from output: %s", binary, versionOutput),
		)
	}

	curVersion := Version{
		mustAtoi(matches[1]),
		mustAtoi(matches[2]),
		mustAtoi(matches[3]),
	}
	// Min version containing SBOM export functionality
	if compareVersions(curVersion, minVersion) >= 0 {
		return nil
	}

	return clierrors.NewGeneralSCAFailureError(
		fmt.Sprintf(
			"%s version %s is not supported. Minimum required version is %s",
			binary,
			formatVersion(curVersion),
			formatVersion(minVersion),
		),
	)
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

func formatVersion(version Version) string {
	versionStrs := []string{}
	for _, v := range version {
		versionStrs = append(versionStrs, strconv.Itoa(v))
	}
	return strings.Join(versionStrs, ".")
}
