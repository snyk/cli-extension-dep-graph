package bun

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ErrBunNotFound is returned when the bun binary is not in PATH.
var ErrBunNotFound = errors.New("bun binary not found in PATH")

// cmdExecutor runs external commands on behalf of the bun plugin.
type cmdExecutor interface {
	Execute(binary, dir string, args ...string) ([]byte, error)
}

// bunCmdExecutor is the production implementation that shells out to bun.
type bunCmdExecutor struct{}

func (e *bunCmdExecutor) Execute(binary, dir string, args ...string) ([]byte, error) {
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, fmt.Errorf("%w", ErrBunNotFound)
	}

	if err := checkBunVersion(resolved); err != nil {
		return nil, err
	}

	cmd := exec.Command(resolved, args...) //nolint:noctx // No context available in this interface.
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("bun %s failed: %w\nstderr: %s", strings.Join(args, " "), err, stderr.String())
	}

	return stdout.Bytes(), nil
}

var (
	minBunVersion = [3]int{1, 1, 0}
	bunVersionRe  = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
)

func checkBunVersion(binary string) error {
	cmd := exec.Command(binary, "--version") //nolint:noctx // No context available in this function.
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get bun version: %w", err)
	}

	ver := strings.TrimSpace(string(out))
	m := bunVersionRe.FindStringSubmatch(ver)

	if len(m) < 4 {
		return fmt.Errorf("could not parse bun version from %q", ver)
	}

	cur := [3]int{atoiSafe(m[1]), atoiSafe(m[2]), atoiSafe(m[3])}

	for i := range cur {
		if cur[i] < minBunVersion[i] {
			return fmt.Errorf(
				"bun %s is below minimum required version %d.%d.%d",
				ver, minBunVersion[0], minBunVersion[1], minBunVersion[2],
			)
		}

		if cur[i] > minBunVersion[i] {
			return nil
		}
	}

	return nil
}

func atoiSafe(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}

	return i
}
