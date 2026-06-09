package pnpm

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

// errPnpmNotFound is returned when the pnpm binary is not in PATH.
var errPnpmNotFound = errors.New("pnpm binary not found in PATH")

// errPnpmVersionTooLow is returned when the installed pnpm is below the minimum.
var errPnpmVersionTooLow = errors.New("pnpm version below minimum required " + minPnpmVersion)

// minPnpmVersion is the minimum pnpm that supports
// `pnpm list --lockfile-only`. The scanner's own pnpm is used (not the repo's
// declared pnpmVersion); modern pnpm reads v5/v6/v9 lockfile formats.
const minPnpmVersion = "v8.0.0"

// pnpmVersionRe extracts MAJOR.MINOR.PATCH from `pnpm --version`, tolerating
// any pre-release/build suffix that would trip strict semver parsing.
var pnpmVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// pnpmListRunner runs `pnpm list` on behalf of the plugin.
type pnpmListRunner interface {
	Run(ctx context.Context, dir string) (io.ReadCloser, error)
}

// pnpmCmdExecutor is the production implementation that shells out to pnpm.
type pnpmCmdExecutor struct{}

var _ pnpmListRunner = (*pnpmCmdExecutor)(nil)

// Run starts `pnpm -r list --lockfile-only --json --depth Infinity` and returns
// a streaming reader over its stdout. `--lockfile-only` resolves the graph from
// the lockfile without touching node_modules (no install). The command runs in
// a goroutine; a non-zero exit surfaces as a read error when the stream is
// exhausted. The caller must Close the returned reader.
func (e *pnpmCmdExecutor) Run(ctx context.Context, dir string) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("pnpm")
	if err != nil {
		return nil, errPnpmNotFound //nolint:wrapcheck // sentinel, intentionally unwrapped
	}

	if err := checkPnpmVersion(ctx, resolved); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, resolved, "-r", "list", "--lockfile-only", "--json", "--depth", "Infinity")
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "NO_COLOR=1")

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("starting pnpm list: %w", err)
	}

	go func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			pw.CloseWithError(fmt.Errorf("pnpm list failed: %w\nstderr: %s", waitErr, stderr.String()))
		} else {
			pw.Close()
		}
	}()

	return pr, nil
}

func checkPnpmVersion(ctx context.Context, binary string) error {
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return fmt.Errorf("failed to get pnpm version: %w", err)
	}

	ver, err := parsePnpmVersion(strings.TrimSpace(string(out)))
	if err != nil {
		return err
	}

	if semver.Compare(ver, minPnpmVersion) < 0 {
		return errPnpmVersionTooLow //nolint:wrapcheck // sentinel, intentionally unwrapped
	}

	return nil
}

// parsePnpmVersion extracts MAJOR.MINOR.PATCH from raw `pnpm --version` output
// and returns it as a canonical Go semver string (e.g. "v8.15.8").
func parsePnpmVersion(raw string) (string, error) {
	m := pnpmVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("could not parse pnpm version from %q", raw)
	}

	return "v" + m[1] + "." + m[2] + "." + m[3], nil
}
