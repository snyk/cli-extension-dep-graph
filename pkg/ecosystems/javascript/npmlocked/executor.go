package npmlocked

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

// RunOptions configure a single npm ls invocation. Zero value is "include
// everything that --all would surface" (the npm ls --all default).
//
// The only currently-modeled knob is OmitDev: it mirrors the legacy Snyk
// CLI's user-facing --dev flag, which is the only option the CLI passes to
// the npm parser today. If more user-facing controls land in the CLI in
// future (optional/peer toggles, etc.) they would be added here.
type RunOptions struct {
	// OmitDev passes --omit=dev to npm ls, suppressing dev dependencies.
	OmitDev bool
}

// npmLsRunner runs `npm ls` on behalf of the npm plugin.
type npmLsRunner interface {
	Run(ctx context.Context, dir string, opts RunOptions) (io.ReadCloser, error)
}

// npmCmdExecutor is the production implementation that shells out to npm.
type npmCmdExecutor struct{}

var _ npmLsRunner = (*npmCmdExecutor)(nil)

// Run invokes `npm ls --json` with version-appropriate flags and returns a
// reader over its stdout JSON.
//
// npm >= 7: `npm ls --json --all --package-lock-only` — resolves the full dep
// tree from the lockfile alone, no node_modules needed.
//
// npm 6: `npm list --json --depth=999`. Without node_modules npm 6 exits
// non-zero, but it still writes a complete, lockfile-derived JSON tree to
// stdout.
//
// Both runners buffer stdout to a bytes.Buffer (not io.Pipe, despite what
// some sibling plugins do). The non-zero exit case is part of the contract
// — npm emits a structured `problems` array alongside a partial-but-usable
// dep tree on out-of-sync / missing-required errors, and we want to surface
// those problems via the logger rather than fail opaquely. That requires
// holding the full JSON in memory long enough to parse it; the same buffer
// is then handed back as the ReadCloser. Stderr is folded into the error
// message only when stdout is empty.
//
// opts.OmitDev is translated to `--omit=dev` on npm >= 7 and to
// `--production` on npm 6 (which predates `--omit`). Both forms exclude
// devDependencies from the resolved tree, matching the legacy
// nodejs-lockfile-parser's default behavior across lockfile versions.
//
// The caller must close the returned ReadCloser.
func (e *npmCmdExecutor) Run(ctx context.Context, dir string, opts RunOptions) (io.ReadCloser, error) {
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
		return runNpmV6(ctx, resolved, dir, opts)
	}

	return runNpmV7Plus(ctx, resolved, dir, opts)
}

// omitFlags returns the `--omit=<class>` flags implied by opts. npm >= 7.
func (o RunOptions) omitFlags() []string {
	var out []string
	if o.OmitDev {
		out = append(out, "--omit=dev")
	}
	return out
}

// v6OmitFlags returns the npm 6 equivalent of omitFlags. npm 6 predates
// `--omit=<class>` (added in npm 7) and uses `--production` to drop
// devDependencies.
func (o RunOptions) v6OmitFlags() []string {
	var out []string
	if o.OmitDev {
		out = append(out, "--production")
	}
	return out
}

// runNpmV7Plus buffers `npm ls --json --all --package-lock-only`. npm exits
// non-zero on minor problems (out-of-sync lockfile, missing deps) while still
// emitting a complete-but-flagged JSON tree on stdout. We tolerate the exit
// code and treat parseable stdout as the success signal — the `problems` field
// in the JSON carries the actionable detail and is surfaced via the logger
// downstream.
//
// stderr is folded into the error message only when stdout is empty (i.e. npm
// genuinely failed to produce any output).
func runNpmV7Plus(ctx context.Context, binary, dir string, opts RunOptions) (io.ReadCloser, error) {
	args := append([]string{"ls", "--json", "--all", "--package-lock-only"}, opts.omitFlags()...)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Exit code is intentionally discarded — see comment above.
	_ = cmd.Run() //nolint:errcheck // exit code is the wrong success signal; parseable stdout is the real signal

	// Surface context cancellation/timeout cleanly. Without this check, a
	// canceled scan would return "no output" instead of the real context
	// error, hiding lifecycle issues from the orchestrator.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("npm ls: %w", ctxErr)
	}

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("npm ls produced no output\nstderr: %s", stderr.String())
	}

	return io.NopCloser(bytes.NewReader(stdout.Bytes())), nil
}

// runNpmV6 buffers stdout from `npm list --json --depth=999`. npm 6 exits
// non-zero when node_modules is absent but writes a complete lockfile-derived
// JSON tree to stdout — we tolerate the exit code, then validate that stdout
// is non-empty and parseable.
//
// OmitDev is translated to `--production`, npm 6's equivalent of npm 7's
// `--omit=dev`. Both exclude devDependencies from the resolved tree.
func runNpmV6(ctx context.Context, binary, dir string, opts RunOptions) (io.ReadCloser, error) {
	args := append([]string{"list", "--json", "--depth=999"}, opts.v6OmitFlags()...)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Ignore the exit code: a missing node_modules dir reliably causes npm 6
	// to exit non-zero even when the JSON output is fully correct. We validate
	// the JSON downstream — that's the real success signal.
	_ = cmd.Run() //nolint:errcheck // exit code is intentionally discarded; see comment above

	// Surface context cancellation/timeout cleanly. Without this check, a
	// canceled scan would return "no output" instead of the real context
	// error, hiding lifecycle issues from the orchestrator.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("npm list: %w", ctxErr)
	}

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
