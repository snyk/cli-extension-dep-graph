package npm

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

// errNpmNotFound is returned when the npm binary is not in PATH.
var errNpmNotFound = errors.New("npm binary not found in PATH")

// errNpmVersionTooLow is returned when the installed npm version is below the
// minimum required (v6.0.0). npm 5 does not produce a usable JSON tree from
// lockfile-only state.
var errNpmVersionTooLow = errors.New("npm version below minimum required " + minNpmVersion)

// minNpmVersion is the minimum npm version this plugin supports.
//
// npm 6 produces a usable JSON tree from the lockfile alone, even though it
// exits non-zero when node_modules is absent (we ignore the exit code in that
// case). npm 7+ supports --package-lock-only for a clean lockfile-only mode.
const minNpmVersion = "v6.0.0"

// npmVersionRe extracts the numeric MAJOR.MINOR.PATCH triplet from `npm --version`
// output. Tolerates prerelease/build suffixes that would defeat strict semver
// parsing (e.g. "10.5.0-beta.1").
var npmVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// npmLsRunner runs `npm ls` on behalf of the npm plugin.
type npmLsRunner interface {
	Run(ctx context.Context, dir string) (io.ReadCloser, error)
}

// npmCmdExecutor is the production implementation that shells out to npm.
type npmCmdExecutor struct{}

var _ npmLsRunner = (*npmCmdExecutor)(nil)

// Run invokes `npm ls --json` with version-appropriate flags and returns a
// reader over its stdout JSON.
//
// npm >= 7: `npm ls --json --all --package-lock-only` — exits 0 on success and
// resolves the full dep tree from the lockfile alone, no node_modules needed.
// Stdout is streamed via io.Pipe so large monorepos don't buffer in RAM.
//
// npm 6: `npm list --json --depth=999`. Without node_modules npm 6 exits
// non-zero, but it still writes a complete, lockfile-derived JSON tree to
// stdout. We capture stdout to a buffer, ignore the exit code, and only
// surface an error if stdout is empty or unparseable. Stderr is folded into
// the error message in that failure path so the user can see what npm said.
//
// The caller must close the returned ReadCloser to release the subprocess.
func (e *npmCmdExecutor) Run(ctx context.Context, dir string) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("npm")
	if err != nil {
		return nil, errNpmNotFound //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	ver, err := detectNpmVersion(ctx, resolved)
	if err != nil {
		return nil, err
	}

	if semver.Compare(ver, minNpmVersion) < 0 {
		return nil, errNpmVersionTooLow //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	major := semver.Major(ver) // "v6", "v7", ...
	if major == "v6" {
		return runNpmV6(ctx, resolved, dir)
	}

	return runNpmV7Plus(ctx, resolved, dir)
}

// runNpmV7Plus streams `npm ls --json --all --package-lock-only`. Lockfile-only
// resolution is supported natively, so any non-zero exit means a real failure
// and is surfaced via the pipe's CloseWithError.
func runNpmV7Plus(ctx context.Context, binary, dir string) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, binary, "ls", "--json", "--all", "--package-lock-only")
	cmd.Dir = dir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("starting npm ls: %w", err)
	}

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			pw.CloseWithError(fmt.Errorf("npm ls failed: %w\nstderr: %s", waitErr, stderr.String()))
		} else {
			pw.Close()
		}
	}()

	return pr, nil
}

// runNpmV6 buffers stdout from `npm list --json --depth=999`. npm 6 exits
// non-zero when node_modules is absent but writes a complete lockfile-derived
// JSON tree to stdout — we tolerate the exit code, then validate that stdout
// is non-empty and parseable.
func runNpmV6(ctx context.Context, binary, dir string) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, binary, "list", "--json", "--depth=999")
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Ignore the exit code: a missing node_modules dir reliably causes npm 6
	// to exit non-zero even when the JSON output is fully correct. We validate
	// the JSON downstream — that's the real success signal.
	_ = cmd.Run() //nolint:errcheck // exit code is intentionally discarded; see comment above

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("npm list produced no output\nstderr: %s", stderr.String())
	}

	return io.NopCloser(bytes.NewReader(stdout.Bytes())), nil
}

// detectNpmVersion runs `npm --version` and normalises the result to a Go
// semver string (e.g. "v10.5.0"). Returns an error if npm cannot be invoked
// or its version string is unrecognizable.
func detectNpmVersion(ctx context.Context, binary string) (string, error) {
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get npm version: %w", err)
	}

	return parseNpmVersion(strings.TrimSpace(string(out)))
}

// parseNpmVersion extracts the MAJOR.MINOR.PATCH triplet from raw `npm --version`
// output and returns it as a canonical Go semver string (e.g. "v10.5.0").
func parseNpmVersion(raw string) (string, error) {
	m := npmVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("could not parse npm version from %q", raw)
	}

	return "v" + m[1] + "." + m[2] + "." + m[3], nil
}
