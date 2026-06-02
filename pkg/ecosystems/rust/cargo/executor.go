package cargo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
)

// errCargoNotFound is returned when the cargo binary is not in PATH.
var errCargoNotFound = errors.New("cargo binary not found in PATH")

// cargoTreeRunner runs `cargo tree` on behalf of the cargo plugin.
type cargoTreeRunner interface {
	Run(ctx context.Context, dir string) (io.ReadCloser, error)
}

// cargoCmdExecutor is the production implementation that shells out to cargo.
type cargoCmdExecutor struct{}

var _ cargoTreeRunner = (*cargoCmdExecutor)(nil)

// cargoTreeArgs is the fixed argument set used to invoke `cargo tree`.
//
// --locked guarantees determinism (forbids Cargo.lock mutations). We don't
// pass --offline: the unified-scanners ethos requires one command that runs
// identically in CLI (warm cache) and SCM (cold cache, cargo fetches on
// demand). --offline would force two code paths.
//
// --all-features enables every feature gate so SCA sees deps that are
// optional behind feature flags. --target=all ignores cfg() platform
// filters so the graph reflects every dep declared, not just those for the
// host triple. --prefix=depth, --no-dedupe and --format={p} shape the
// output for the parser added in the next commit.
var cargoTreeArgs = []string{
	"tree",
	"--locked",
	"--all-features",
	"--target=all",
	"--edges=normal,build",
	"--prefix=depth",
	"--no-dedupe",
	"--format={p}",
}

// Run starts `cargo tree` and returns a streaming reader over its stdout.
// The command runs in a goroutine; any non-zero exit is surfaced as a read
// error when the caller exhausts the stream. The caller must close the
// returned ReadCloser when done.
func (e *cargoCmdExecutor) Run(ctx context.Context, dir string) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("cargo")
	if err != nil {
		return nil, errCargoNotFound //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	cmd := exec.CommandContext(ctx, resolved, cargoTreeArgs...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "NO_COLOR=1")

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	pr, pw := io.Pipe()

	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("starting cargo tree: %w", err)
	}

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			pw.CloseWithError(fmt.Errorf("cargo tree failed: %w\nstderr: %s", waitErr, stderr.String()))
		} else {
			pw.Close()
		}
	}()

	return pr, nil
}
