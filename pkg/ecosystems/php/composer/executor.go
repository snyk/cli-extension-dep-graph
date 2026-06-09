package composer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// errComposerNotFound is returned when the composer binary is not in PATH.
var errComposerNotFound = errors.New("composer binary not found in PATH")

// errComposerVersionTooLow is returned when the installed composer version
// is below the minimum required. Composer 1.x is intentionally unsupported:
// the `--locked` flag landed in 2.x, and 1.x is out of upstream support.
var errComposerVersionTooLow = errors.New("composer version below minimum required " + minComposerVersion)

// minComposerVersion is the minimum composer version the plugin supports.
// 2.0.0 is the first release with `composer show --locked`, which is the
// flag that lets us resolve from composer.lock without a populated
// vendor/ directory.
const minComposerVersion = "v2.0.0"

// composerVersionRe extracts the numeric MAJOR.MINOR.PATCH triplet from
// `composer --version` output. The full string looks like
//
//	"Composer version 2.7.6 2024-05-04 23:03:15"
//
// We tolerate prerelease/build suffixes and any preamble noise.
var composerVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// RunOptions configure a single composer show invocation.
//
// IncludeDev, when true, leaves `require-dev` packages in the tree. The
// zero value (false) passes `--no-dev`, matching the legacy snyk-php-plugin
// default and the Snyk CLI's user-facing behavior when `--dev` is absent.
type RunOptions struct {
	// IncludeDev controls whether require-dev entries appear in the output.
	IncludeDev bool
}

// composerShowRunner runs `composer show` on behalf of the composer plugin.
type composerShowRunner interface {
	Run(ctx context.Context, dir string, opts RunOptions) (io.ReadCloser, error)
}

// composerCmdExecutor is the production implementation that shells out to
// composer.
type composerCmdExecutor struct{}

var _ composerShowRunner = (*composerCmdExecutor)(nil)

// Run invokes `composer show --locked --tree --no-interaction --no-ansi`
// (plus `--no-dev` when opts.IncludeDev is false) in dir and returns a
// reader over its stdout text-tree output.
//
// Offline guarantees:
//   - `--locked` reads composer.lock; vendor/ is not required and is not
//     created.
//   - COMPOSER_DISABLE_NETWORK=1 is set in the child environment as a
//     belt-and-braces guard against any subcommand that would otherwise
//     attempt a network fetch.
//   - The plugin never invokes `composer install` and never mutates the
//     project directory.
//
// `--no-interaction` suppresses prompts; `--no-ansi` strips colour escape
// codes so the parser sees a deterministic byte stream regardless of the
// caller's TTY state.
//
// Caller must close the returned ReadCloser.
func (e *composerCmdExecutor) Run(ctx context.Context, dir string, opts RunOptions) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("composer")
	if err != nil {
		return nil, errComposerNotFound //nolint:wrapcheck // sentinel error
	}

	ver, err := detectComposerVersion(ctx, resolved)
	if err != nil {
		return nil, err
	}

	if semver.Compare(ver, minComposerVersion) < 0 {
		return nil, errComposerVersionTooLow //nolint:wrapcheck // sentinel error
	}

	return runComposerShow(ctx, resolved, dir, opts)
}

// composerEnv returns the environment for a composer invocation, with
// COMPOSER_DISABLE_NETWORK=1 forced on top of the parent environment.
// Existing user-set values are overridden — the plugin's contract is
// offline-only and we don't let the host environment break that.
func composerEnv() []string {
	parent := os.Environ()
	out := make([]string, 0, len(parent)+1)
	for _, kv := range parent {
		if strings.HasPrefix(kv, "COMPOSER_DISABLE_NETWORK=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "COMPOSER_DISABLE_NETWORK=1")
	return out
}

// composerArgs returns the argv for `composer show` with the given options
// applied. Extracted so tests can assert on the exact CLI surface.
func composerArgs(opts RunOptions) []string {
	args := []string{"show", "--locked", "--tree", "--no-interaction", "--no-ansi"}
	if !opts.IncludeDev {
		args = append(args, "--no-dev")
	}
	return args
}

// runComposerShow streams `composer show --locked --tree` stdout to the
// caller via an io.Pipe so large dep trees don't buffer in RAM. Stderr is
// captured in a bounded buffer so failure messages remain attached to the
// error.
func runComposerShow(ctx context.Context, binary, dir string, opts RunOptions) (io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, binary, composerArgs(opts)...)
	cmd.Dir = dir
	cmd.Env = composerEnv()

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("starting composer show: %w", err)
	}

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			_ = pw.CloseWithError(fmt.Errorf(
				"composer show failed: %w\nstderr: %s", waitErr, stderr.String()))
			return
		}
		_ = pw.Close()
	}()

	return pr, nil
}

// detectComposerVersion runs `composer --version` and normalises the
// result to a Go semver string (e.g. "v2.7.6"). Returns an error if
// composer cannot be invoked or its version string is unrecognizable.
func detectComposerVersion(ctx context.Context, binary string) (string, error) {
	out, err := exec.CommandContext(ctx, binary, "--version", "--no-ansi").Output()
	if err != nil {
		return "", fmt.Errorf("failed to get composer version: %w", err)
	}
	return parseComposerVersion(strings.TrimSpace(string(out)))
}

// parseComposerVersion extracts the MAJOR.MINOR.PATCH triplet from raw
// `composer --version` output and returns it as a canonical Go semver
// string. Returns an error when no version-shaped token is present.
func parseComposerVersion(raw string) (string, error) {
	m := composerVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("could not parse composer version from %q", raw)
	}
	return "v" + m[1] + "." + m[2] + "." + m[3], nil
}
