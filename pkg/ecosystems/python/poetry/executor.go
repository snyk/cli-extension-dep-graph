package poetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	// poetryBinary is the executable name we shell out to. We don't
	// support overriding it through CLI options yet — the legacy plugin
	// doesn't either.
	poetryBinary = "poetry"

	// disableVirtualenvEnv prevents poetry from materialising a venv
	// for the subcommand. Combined with `show --tree` (which is read-only
	// against poetry.lock) this guarantees no install side effects.
	disableVirtualenvEnv = "POETRY_VIRTUALENVS_CREATE=false"

	// minPoetryVersion is the lowest poetry release we test against.
	// 1.5 is when `--no-ansi` and lockfile-only `show` were reliably
	// stable; below that the tree formatting drifts and we'd need extra
	// special-casing we'd rather not maintain.
	minPoetryMajor = 1
	minPoetryMinor = 5
)

// sentinel errors so callers can decide whether to surface "tool missing"
// to the user or fall back to the legacy plugin.
var (
	// errPoetryNotFound is returned when the poetry binary is missing
	// from PATH. Sentinel so plugin.go can wrap it with a user-facing
	// install hint.
	errPoetryNotFound = errors.New("poetry binary not found in PATH")

	// errPoetryVersionTooLow is returned when the installed poetry
	// release is older than the minimum we support.
	errPoetryVersionTooLow = fmt.Errorf("poetry version below minimum required %d.%d", minPoetryMajor, minPoetryMinor)
)

// poetryVersionRe pulls the MAJOR.MINOR.PATCH triple out of `poetry --version`
// output. Output shape: `Poetry (version 1.7.1)` on most releases, but we
// stay tolerant of any preamble/suffix.
var poetryVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// poetryRunner runs `poetry show --tree` on behalf of the plugin. Kept as
// an interface so tests can stub it without spawning the real binary.
type poetryRunner interface {
	// Run launches the poetry subcommand for the given project directory
	// and returns a streaming reader over its stdout. The caller MUST
	// Close the returned reader to release the subprocess goroutine.
	//
	// includeDev controls whether dev/group dependencies appear in the
	// tree: poetry includes them by default, so when includeDev is false
	// we add `--without dev` to suppress the legacy `[tool.poetry.group.dev]`
	// group (the most common case; matching the legacy parser's behaviour).
	Run(ctx context.Context, dir string, includeDev bool) (io.ReadCloser, error)
}

// poetryCmdExecutor is the production implementation that shells out to
// the real poetry binary.
type poetryCmdExecutor struct{}

var _ poetryRunner = (*poetryCmdExecutor)(nil)

// Run starts `poetry show --tree --no-ansi` and streams stdout via
// io.Pipe. POETRY_VIRTUALENVS_CREATE=false is set in the subprocess
// environment so poetry will not create or activate a virtualenv —
// this is the offline guarantee.
func (e *poetryCmdExecutor) Run(ctx context.Context, dir string, includeDev bool) (io.ReadCloser, error) {
	resolved, err := exec.LookPath(poetryBinary)
	if err != nil {
		return nil, errPoetryNotFound //nolint:wrapcheck // sentinel, intentionally bare
	}

	if err := checkPoetryVersion(ctx, resolved); err != nil {
		return nil, err
	}

	args := []string{"show", "--tree", "--no-ansi"}
	if !includeDev {
		// Suppress the conventional dev group. Older poetry releases
		// accepted `--no-dev` (now removed); `--without dev` works on
		// every release in our supported range (1.5+).
		args = append(args, "--without", "dev")
	}

	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Dir = dir
	// Append (not replace) so PATH and other essentials are preserved,
	// but our virtualenv-off override wins.
	cmd.Env = append(cmd.Environ(), disableVirtualenvEnv)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("starting poetry show: %w", err)
	}

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			pw.CloseWithError(fmt.Errorf("poetry show failed: %w\nstderr: %s", waitErr, stderr.String()))
			return
		}
		pw.Close()
	}()

	return pr, nil
}

// checkPoetryVersion runs `poetry --version` and rejects releases older
// than the minimum we support. Returns errPoetryVersionTooLow so the
// caller can surface a user-actionable message.
func checkPoetryVersion(ctx context.Context, binary string) error {
	out, err := exec.CommandContext(ctx, binary, "--version", "--no-ansi").Output()
	if err != nil {
		return fmt.Errorf("failed to get poetry version: %w", err)
	}

	major, minor, _, err := parsePoetryVersion(strings.TrimSpace(string(out)))
	if err != nil {
		return err
	}

	if major < minPoetryMajor || (major == minPoetryMajor && minor < minPoetryMinor) {
		return errPoetryVersionTooLow //nolint:wrapcheck // sentinel, intentionally bare
	}

	return nil
}

// parsePoetryVersion extracts the MAJOR.MINOR.PATCH triple from raw
// `poetry --version` output. Returns an error if no version pattern is
// present.
func parsePoetryVersion(raw string) (major, minor, patch int, err error) {
	m := poetryVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return 0, 0, 0, fmt.Errorf("could not parse poetry version from %q", raw)
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return major, minor, patch, nil
}
