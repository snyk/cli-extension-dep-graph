package swiftpm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// errSwiftNotFound is returned when the swift binary is not in PATH.
var errSwiftNotFound = errors.New("swift binary not found in PATH")

// errSwiftVersionTooLow is returned when the installed swift version is below
// the minimum required for `swift package show-dependencies --format json`.
var errSwiftVersionTooLow = errors.New("swift version below minimum required " + minSwiftVersion)

// minSwiftVersion is the minimum swift toolchain version this plugin
// supports.
//
// `swift package show-dependencies --format json` exists in 5.6+ and is the
// command we delegate to. Earlier toolchains only support `text` and `dot`
// output formats, which would require us to ship our own parser.
const minSwiftVersion = "v5.6.0"

// swiftVersionRe extracts the numeric MAJOR.MINOR.PATCH triplet from
// `swift --version` output. The full string is multiline and starts with
// noise like "swift-driver version: 1.84.1 Apple Swift version 5.9.2 ..." —
// the regex anchors on "Swift version".
var swiftVersionRe = regexp.MustCompile(`Swift version (\d+)\.(\d+)(?:\.(\d+))?`)

// swiftRunner runs `swift package show-dependencies` on behalf of the plugin.
type swiftRunner interface {
	Run(ctx context.Context, dir string, extraArgs []string) (io.ReadCloser, error)
}

// swiftCmdExecutor is the production implementation that shells out to swift.
type swiftCmdExecutor struct{}

var _ swiftRunner = (*swiftCmdExecutor)(nil)

// Run invokes `swift package --package-path <dir> show-dependencies --format json`
// and returns a reader over its stdout JSON.
//
// stdout is streamed via io.Pipe so large trees don't buffer in RAM. stderr
// is captured to a buffer and folded into the error message on failure so
// the user can see what swift said (it logs fetch/resolve progress lines to
// stderr even on success).
//
// The caller must close the returned ReadCloser to release the subprocess.
//
// extraArgs are appended after `package` but before `--package-path`,
// matching the legacy plugin's `--args` passthrough position. The legacy
// plugin only ever forwarded arbitrary args here; no `--dev`, `--exclude`
// or other typed flags exist for swift.
func (e *swiftCmdExecutor) Run(ctx context.Context, dir string, extraArgs []string) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("swift")
	if err != nil {
		return nil, errSwiftNotFound //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	ver, err := detectSwiftVersion(ctx, resolved)
	if err != nil {
		return nil, err
	}

	if semver.Compare(ver, minSwiftVersion) < 0 {
		return nil, errSwiftVersionTooLow //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	return runSwiftShowDeps(ctx, resolved, dir, extraArgs)
}

// runSwiftShowDeps spawns swift and pipes stdout back to the caller.
func runSwiftShowDeps(ctx context.Context, binary, dir string, extraArgs []string) (io.ReadCloser, error) {
	args := []string{"package"}
	args = append(args, extraArgs...)
	args = append(args,
		"--package-path", dir,
		"show-dependencies",
		"--format", "json",
	)

	cmd := exec.CommandContext(ctx, binary, args...)
	// We intentionally do NOT set cmd.Dir to dir; --package-path drives swift's
	// project root selection, and leaving cwd untouched avoids any subtle
	// behaviour where swift writes ancillary files into the test cwd.

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("starting swift package: %w", err)
	}

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			pw.CloseWithError(fmt.Errorf("swift package show-dependencies failed: %w\nstderr: %s", waitErr, stderr.String()))
		} else {
			pw.Close()
		}
	}()

	return pr, nil
}

// detectSwiftVersion runs `swift --version` and normalises the result to a Go
// semver string (e.g. "v5.9.2"). Returns an error if swift cannot be invoked
// or its version string is unrecognizable.
func detectSwiftVersion(ctx context.Context, binary string) (string, error) {
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get swift version: %w", err)
	}

	return parseSwiftVersion(strings.TrimSpace(string(out)))
}

// parseSwiftVersion extracts the MAJOR.MINOR.PATCH triplet from raw
// `swift --version` output and returns it as a canonical Go semver string
// (e.g. "v5.9.2"). The patch component is optional — older toolchains omit
// it (e.g. "Apple Swift version 5.6") in which case we default it to "0".
func parseSwiftVersion(raw string) (string, error) {
	m := swiftVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("could not parse swift version from %q", raw)
	}

	patch := m[3]
	if patch == "" {
		patch = "0"
	}

	return "v" + m[1] + "." + m[2] + "." + patch, nil
}
