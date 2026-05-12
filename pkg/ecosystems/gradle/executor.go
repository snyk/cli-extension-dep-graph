package gradle

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	// snykDepsMarker is the prefix the init script prints on the line that
	// contains the absolute path to the generated NDJSON output file.
	snykDepsMarker = "SNYK_DEPS_NDJSON "
)

// runInitScript runs `gradle :snykDependencyGraph` with the embedded init script
// and returns a ReadCloser for the generated NDJSON file.
//
// Always uses `:snykDependencyGraph` to run the task on the root project since
// the task only exists at the root level.
//
// Fixed flags applied on every invocation:
//
//	--no-daemon          avoid background daemon processes
//	--console=plain      suppress progress animations that pollute output
//	-Dorg.gradle.welcome=never       suppress "Welcome to Gradle" banner
//
// The returned ReadCloser must be closed by the caller. The NDJSON output is written
// to <projectDir>/build/reports/snyk-dependency-graph.ndjson with a fixed name, so it
// is overwritten on each invocation rather than accumulating. It lives in Gradle's
// build directory and is cleaned by `gradle clean` along with other build artifacts.
// Preserved between runs as a debugging aid.
func runInitScript(ctx context.Context, projectDir, gradleBinary, initScriptPath string, extraArgs []string) (io.ReadCloser, error) {
	args := append([]string{
		"--init-script", initScriptPath,
		"--no-daemon",
		"--console=plain",
		"-Dorg.gradle.welcome=never",
		":snykDependencyGraph",
	}, extraArgs...)

	cmd := exec.CommandContext(ctx, gradleBinary, args...)
	cmd.Dir = projectDir

	// Use streaming for stdout to handle potentially large output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start gradle in %s: %w", projectDir, err)
	}

	// Stream stdout to find the marker line without buffering everything
	outputFile, err := parseSnykDepsMarkerFromStream(stdout)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to parse gradle output in %s: %w\nstderr:\n%s",
			projectDir, err, stderr.String(),
		)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf(
			"gradle execution failed in %s: %w\nstderr:\n%s",
			projectDir, err, stderr.String(),
		)
	}

	if outputFile == "" {
		return nil, fmt.Errorf(
			"gradle task ran successfully but did not output expected marker line %q\nstderr:\n%s",
			snykDepsMarker, stderr.String(),
		)
	}

	// Return ReadCloser for the JSON file (preserved for debugging)
	return newFileReadCloser(outputFile)
}

// parseSnykDepsMarkerFromStream scans Gradle's stdout stream for the line emitted by
// the init script: "SNYK_DEPS_NDJSON /absolute/path/to/file.ndjson".
// Returns the file path when found, empty string if not found, or an error if multiple
// marker lines are detected (which could indicate tampering or malicious behavior).
func parseSnykDepsMarkerFromStream(stdout io.Reader) (string, error) {
	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024*1024) // 1GB max token size
	var foundPath string
	var markerCount int

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, snykDepsMarker) {
			markerCount++
			if markerCount > 1 {
				return "", fmt.Errorf("multiple SNYK_DEPS_NDJSON marker lines detected, possible tampering attempt")
			}
			foundPath = strings.TrimSpace(strings.TrimPrefix(line, snykDepsMarker))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading gradle stdout: %w", err)
	}
	return foundPath, nil
}

// newFileReadCloser opens the specified file and returns a ReadCloser.
// The file is preserved after closing for debugging purposes.
func newFileReadCloser(filePath string) (io.ReadCloser, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open gradle output file %s: %w", filePath, err)
	}
	return file, nil
}
