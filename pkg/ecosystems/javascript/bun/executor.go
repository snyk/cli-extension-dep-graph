package bun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// errBunNotFound is returned when the bun binary is not in PATH.
var errBunNotFound = fmt.Errorf("bun binary not found in PATH")

// errBunVersionTooLow is returned when the installed bun version is below the minimum required.
var errBunVersionTooLow = fmt.Errorf("bun version below minimum required %d.%d.%d", minBunMajor, minBunMinor, minBunPatch)

const (
	minBunMajor = 1
	minBunMinor = 2
	minBunPatch = 19
)

// bunWhyRunner runs `bun why` on behalf of the bun plugin.
type bunWhyRunner interface {
	Run(ctx context.Context, dir string) (io.Reader, error)
}

// bunCmdExecutor is the production implementation that shells out to bun.
type bunCmdExecutor struct{}

var _ bunWhyRunner = (*bunCmdExecutor)(nil)

// Run starts `bun why '*' --top` and returns a streaming reader over its stdout.
// The command runs in a goroutine; any non-zero exit is surfaced as a read error
// when the caller exhausts the stream.
func (e *bunCmdExecutor) Run(ctx context.Context, dir string) (io.Reader, error) {
	resolved, err := exec.LookPath("bun")
	if err != nil {
		return nil, errBunNotFound
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

var bunVersionRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

func checkBunVersion(ctx context.Context, binary string) error {
	out, err := exec.CommandContext(ctx, binary, "--version").Output()
	if err != nil {
		return fmt.Errorf("failed to get bun version: %w", err)
	}

	m := bunVersionRe.FindStringSubmatch(strings.TrimSpace(string(out)))
	if len(m) < 4 {
		return fmt.Errorf("could not parse bun version from %q", strings.TrimSpace(string(out)))
	}

	major, err := strconv.Atoi(m[1])
	if err != nil {
		return fmt.Errorf("could not parse bun major version component %q: %w", m[1], err)
	}

	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return fmt.Errorf("could not parse bun minor version component %q: %w", m[2], err)
	}

	patch, err := strconv.Atoi(m[3])
	if err != nil {
		return fmt.Errorf("could not parse bun patch version component %q: %w", m[3], err)
	}

	minVersion := [3]int{minBunMajor, minBunMinor, minBunPatch}
	curVersion := [3]int{major, minor, patch}

	for i := range curVersion {
		if curVersion[i] > minVersion[i] {
			return nil
		}

		if curVersion[i] < minVersion[i] {
			return errBunVersionTooLow
		}
	}

	return nil
}
