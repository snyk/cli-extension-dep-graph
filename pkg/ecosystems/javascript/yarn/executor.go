package yarn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// errYarnNotFound is returned when the yarn binary is not in PATH.
var errYarnNotFound = errors.New("yarn binary not found in PATH")

// errYarnVersionUnsupported is returned when yarn's reported version is
// outside the supported range (currently: any v1.x or v2.x+).
var errYarnVersionUnsupported = errors.New("yarn version not supported")

// yarnVersionRe extracts MAJOR.MINOR.PATCH from `yarn --version` output,
// tolerating prereleases and build metadata suffixes.
var yarnVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// yarnFamily distinguishes Classic v1 from Berry v2+ — the two have entirely
// different CLI surfaces (yarn list vs yarn info) and output shapes.
type yarnFamily int

const (
	familyUnknown yarnFamily = iota
	familyClassic            // yarn 1.x
	familyBerry              // yarn 2.x, 3.x, 4.x
)

// yarnRunResult carries the streaming stdout of a yarn invocation plus the
// metadata a parser needs to pick the right format and report version info.
type yarnRunResult struct {
	Output  io.ReadCloser
	Family  yarnFamily
	Version string // MAJOR.MINOR.PATCH, no "v" prefix
}

// yarnRunner runs yarn list / yarn info on behalf of the yarn plugin.
type yarnRunner interface {
	Run(ctx context.Context, dir string) (*yarnRunResult, error)
}

// yarnCmdExecutor is the production implementation that shells out to yarn.
type yarnCmdExecutor struct{}

var _ yarnRunner = (*yarnCmdExecutor)(nil)

// Run detects yarn's version, picks the right install-free command, and
// returns a streaming reader over its stdout.
//
//   - Classic (v1): `yarn list --depth=Infinity --json --frozen-lockfile
//     --no-progress --non-interactive`. Reads yarn.lock directly; needs no
//     env redirection and creates nothing on disk.
//
//   - Berry (v2+):  `yarn info --all --recursive --json`. Would otherwise write
//     `.yarn/install-state.gz` and `.yarn/cache/` into the project dir; we
//     redirect both to a tmp dir via YARN_GLOBAL_FOLDER /
//     YARN_INSTALL_STATE_PATH so the user's project is untouched. Network
//     access is disabled via YARN_ENABLE_NETWORK=false so a scan can't fetch
//     packages even if the redirected cache is empty.
//
// The subprocess runs in a goroutine; non-zero exit surfaces as a read error
// when the caller exhausts the stream. The caller must close the returned
// ReadCloser to release the goroutine and any tmp dir created for Berry.
func (e *yarnCmdExecutor) Run(ctx context.Context, dir string) (*yarnRunResult, error) {
	resolved, err := exec.LookPath(pkgManager)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errYarnNotFound, err)
	}

	family, version, err := detectYarnFamily(ctx, resolved, dir)
	if err != nil {
		return nil, err
	}

	var (
		cmd      *exec.Cmd
		extraEnv = append(os.Environ(), "NO_COLOR=1")
		tmpDir   string
	)

	switch family {
	case familyClassic:
		cmd = exec.CommandContext(
			ctx, resolved,
			"list",
			"--depth=Infinity",
			"--json",
			"--frozen-lockfile",
			"--no-progress",
			"--non-interactive",
		)

	case familyBerry:
		tmpDir, err = os.MkdirTemp("", "snyk-yarn-berry-*")
		if err != nil {
			return nil, fmt.Errorf("creating yarn temp dir: %w", err)
		}
		stateFile := filepath.Join(tmpDir, "install-state.gz")
		cmd = exec.CommandContext(
			ctx, resolved,
			"info",
			"--all",
			"--recursive",
			"--json",
		)
		// `yarn info --all --recursive --json` walks the lockfile and does
		// not need package contents — verified empirically against a fresh
		// (empty) global folder. YARN_ENABLE_NETWORK=false turns that
		// observation into an enforced contract: if a future Berry version,
		// an unusual lockfile, or an unusual locator type ever needs to
		// fetch, we fail loudly instead of silently downloading.
		extraEnv = append(
			extraEnv,
			"YARN_GLOBAL_FOLDER="+tmpDir,
			"YARN_ENABLE_GLOBAL_CACHE=true",
			"YARN_INSTALL_STATE_PATH="+stateFile,
			"YARN_ENABLE_NETWORK=false",
		)

	default:
		return nil, fmt.Errorf("%w: %s", errYarnVersionUnsupported, version)
	}

	cmd.Dir = dir
	cmd.Env = extraEnv

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	pr, pw := io.Pipe()
	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		if tmpDir != "" {
			_ = os.RemoveAll(tmpDir)
		}
		return nil, fmt.Errorf("starting yarn: %w", err)
	}

	go func() {
		waitErr := cmd.Wait()
		if tmpDir != "" {
			_ = os.RemoveAll(tmpDir)
		}
		if waitErr != nil {
			pw.CloseWithError(fmt.Errorf("yarn failed: %w\nstderr: %s", waitErr, stderr.String()))
		} else {
			pw.Close()
		}
	}()

	return &yarnRunResult{
		Output:  pr,
		Family:  family,
		Version: version,
	}, nil
}

// detectYarnFamily runs `yarn --version` inside dir (so corepack-managed
// projects report the project-pinned version, not the system default) and
// classifies it into a family.
func detectYarnFamily(ctx context.Context, binary, dir string) (yarnFamily, string, error) {
	cmd := exec.CommandContext(ctx, binary, "--version")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return familyUnknown, "", fmt.Errorf("failed to get yarn version: %w", err)
	}

	ver, err := parseYarnVersion(strings.TrimSpace(string(out)))
	if err != nil {
		return familyUnknown, "", err
	}

	// ver is "MAJOR.MINOR.PATCH" from parseYarnVersion's regex — first
	// segment is guaranteed to be a numeric literal, so Atoi cannot fail.
	major, _ := strconv.Atoi(strings.Split(ver, ".")[0]) //nolint:errcheck // regex group is \d+, cannot fail
	switch {
	case major == 1:
		return familyClassic, ver, nil
	case major >= 2:
		return familyBerry, ver, nil
	default:
		return familyUnknown, ver, fmt.Errorf("%w: %s", errYarnVersionUnsupported, ver)
	}
}

// parseYarnVersion extracts MAJOR.MINOR.PATCH from raw `yarn --version` output.
// Returns just the numeric triplet (no "v" prefix) — callers that want semver
// comparisons can add their own.
func parseYarnVersion(raw string) (string, error) {
	m := yarnVersionRe.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("could not parse yarn version from %q", raw)
	}
	return m[1] + "." + m[2] + "." + m[3], nil
}
