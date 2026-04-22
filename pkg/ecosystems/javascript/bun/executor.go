package bun

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

// errBunNotFound is returned when the bun binary is not in PATH.
var errBunNotFound = errors.New("bun binary not found in PATH")

// errBunVersionTooLow is returned when the installed bun version is below the minimum required.
var errBunVersionTooLow = errors.New("bun version below minimum required " + minBunVersion)

// minBunVersion is the minimum bun version that supports `bun why '*' --top`.
const minBunVersion = "v1.2.19"

// bunVersionRe extracts the numeric MAJOR.MINOR.PATCH triplet from `bun --version`
// output. Using a regex instead of assuming a bare semver string means the check
// tolerates unconventional suffixes (e.g. canary builds, build metadata) that
// would cause semver.IsValid to return false.
var bunVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// bunWhyRunner runs `bun why` on behalf of the bun plugin.
type bunWhyRunner interface {
	Run(ctx context.Context, dir string) (io.ReadCloser, error)
}

// bunCmdExecutor is the production implementation that shells out to bun.
type bunCmdExecutor struct{}

var _ bunWhyRunner = (*bunCmdExecutor)(nil)

// Run starts `bun why '*' --top` and returns a streaming reader over its stdout.
// The command runs in a goroutine; any non-zero exit is surfaced as a read error
// when the caller exhausts the stream.
//
// The caller must close the returned ReadCloser when done (or on error) to
// ensure the background goroutine and subprocess are released promptly.
func (e *bunCmdExecutor) Run(ctx context.Context, dir string) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("bun")
	if err != nil {
		return nil, errBunNotFound //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	if err := checkBunVersion(ctx, resolved); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, resolved, "why", "*", "--top")
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "NO_COLOR=1")

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	pr, pw := io.Pipe()

	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("starting bun why: %w", err)
	}

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			pw.CloseWithError(fmt.Errorf("bun why failed: %w\nstderr: %s", waitErr, stderr.String()))
		} else {
			pw.Close()
		}
	}()

	return pr, nil
}

func checkBunVersion(ctx context.Context, binary string) error {
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return fmt.Errorf("failed to get bun version: %w", err)
	}

	ver, err := parseBunVersion(strings.TrimSpace(string(out)))
	if err != nil {
		return err
	}

	if semver.Compare(ver, minBunVersion) < 0 {
		return errBunVersionTooLow //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	return nil
}

// parseBunVersion extracts the MAJOR.MINOR.PATCH version from raw `bun --version`
// output and returns it as a canonical Go semver string (e.g. "v1.2.19").
//
// A regex is used rather than direct semver parsing so that builds with
// unconventional suffixes (canary tags, build metadata) are still accepted.
func parseBunVersion(raw string) (string, error) {
	m := bunVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("could not parse bun version from %q", raw)
	}

	return "v" + m[1] + "." + m[2] + "." + m[3], nil
}
