package gradle

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	// snykDepsMarker is the prefix the init script prints on the line that
	// contains the absolute path to the generated JSON output file.
	snykDepsMarker = "SNYK_DEPS_JSON "

	// fallbackReportPath is used when the marker line is not found in stdout.
	fallbackReportPath = "build/reports/snyk-dependency-graph.json"
)

// runInitScript runs `gradle snykDependencyGraph` with the embedded init script
// and returns the raw JSON bytes from the generated output file.
//
// Fixed flags applied on every invocation:
//
//	--no-daemon          avoid background daemon processes
//	--no-parallel        required for correctness on certain multi-project builds
//	--console=plain      suppress progress animations that pollute output
//	-Dorg.gradle.welcome=never       suppress "Welcome to Gradle" banner
func runInitScript(ctx context.Context, projectDir, gradleBinary, initScriptPath string, extraArgs []string) ([]byte, error) {
	args := append([]string{
		"--init-script", initScriptPath,
		"--no-daemon",
		"--no-parallel",
		"--console=plain",
		"-Dorg.gradle.welcome=never",
		"snykDependencyGraph",
	}, extraArgs...)

	cmd := exec.CommandContext(ctx, gradleBinary, args...)
	cmd.Dir = projectDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf(
			"gradle execution failed in %s: %w\nstdout:\n%s\nstderr:\n%s",
			projectDir, err, stdout.String(), stderr.String(),
		)
	}

	outputFile := parseSnykDepsMarker(stdout.String())
	if outputFile == "" {
		outputFile = filepath.Join(projectDir, fallbackReportPath)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf(
			"gradle ran successfully but could not read output file %s: %w\nstdout:\n%s",
			outputFile, err, stdout.String(),
		)
	}

	return data, nil
}

// parseSnykDepsMarker scans Gradle's combined output for the line emitted by
// the init script: "SNYK_DEPS_JSON /absolute/path/to/file.json".
func parseSnykDepsMarker(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, snykDepsMarker) {
			return strings.TrimPrefix(line, snykDepsMarker)
		}
	}
	return ""
}
