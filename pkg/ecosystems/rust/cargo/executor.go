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

// cargoRunner runs `cargo tree` and `cargo metadata` on behalf of the cargo
// plugin. The two methods are grouped on a single interface because the
// production implementation is one cargo binary; splitting them would buy
// nothing test-wise and complicate the Plugin's executor wiring.
type cargoRunner interface {
	// RunTree invokes `cargo tree` in dir. If pkg is non-empty, the run is
	// scoped to that workspace member (`-p <pkg>`); otherwise cargo picks the
	// default package (errors in virtual workspaces).
	RunTree(ctx context.Context, dir string, pkg string) (io.ReadCloser, error)

	// RunMetadata invokes `cargo metadata --no-deps --format-version=1` in dir.
	// Used to enumerate workspace members and their manifest paths.
	RunMetadata(ctx context.Context, dir string) (io.ReadCloser, error)
}

// cargoCmdExecutor is the production implementation that shells out to cargo.
type cargoCmdExecutor struct{}

var _ cargoRunner = (*cargoCmdExecutor)(nil)

// baseTreeArgs is the fixed argument set used to invoke `cargo tree`.
// See the package documentation for why each flag is chosen.
var baseTreeArgs = []string{
	"tree",
	"--locked",
	"--all-features",
	"--target=all",
	"--edges=normal,build",
	"--prefix=depth",
	"--no-dedupe",
	"--format={p}",
}

// baseMetadataArgs invokes cargo metadata. --no-deps keeps the JSON to just
// the workspace's own packages (no resolved transitive graph), which is all
// we need for member enumeration and bounds memory at any project size.
// --locked matches the strictness applied to cargo tree.
var baseMetadataArgs = []string{
	"metadata",
	"--no-deps",
	"--format-version=1",
	"--locked",
}

// RunTree starts `cargo tree` and returns a streaming reader over its stdout.
// Caller must close the returned ReadCloser when done.
func (e *cargoCmdExecutor) RunTree(ctx context.Context, dir string, pkg string) (io.ReadCloser, error) {
	args := append([]string(nil), baseTreeArgs...)
	if pkg != "" {
		args = append(args, "-p", pkg)
	}
	return e.run(ctx, dir, args, "cargo tree")
}

// RunMetadata starts `cargo metadata --no-deps` and returns a streaming
// reader over its stdout. Same caller-closes contract as RunTree.
func (e *cargoCmdExecutor) RunMetadata(ctx context.Context, dir string) (io.ReadCloser, error) {
	return e.run(ctx, dir, baseMetadataArgs, "cargo metadata")
}

// run is the shared subprocess driver for both cargo tree and cargo metadata.
// It looks up cargo, starts the command, and pipes stdout back to the caller.
// Non-zero exits are surfaced via the stream's read error, with stderr
// appended to the message for debuggability.
func (e *cargoCmdExecutor) run(
	ctx context.Context,
	dir string,
	args []string,
	subcommandLabel string,
) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("cargo")
	if err != nil {
		return nil, errCargoNotFound //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Dir = dir
	cmd.Env = append(cmd.Environ(), "NO_COLOR=1")

	var stderr bytes.Buffer

	cmd.Stderr = &stderr

	pr, pw := io.Pipe()

	cmd.Stdout = pw

	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return nil, fmt.Errorf("starting %s: %w", subcommandLabel, err)
	}

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			pw.CloseWithError(fmt.Errorf("%s failed: %w\nstderr: %s", subcommandLabel, waitErr, stderr.String()))
		} else {
			pw.Close()
		}
	}()

	return pr, nil
}
