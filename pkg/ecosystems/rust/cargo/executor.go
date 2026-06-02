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

// cargoTreeOpts configures a single `cargo tree` invocation.
//
// Pkg scopes the run to a single workspace member via `-p <Pkg>`; empty
// means no scoping (cargo picks the default package or errors for virtual
// workspaces).
//
// IncludeDev controls whether dev-dependencies are walked. Default false
// matches Cargo's own default (`--edges=normal,build`). Setting true adds
// `dev` to the edges list (`--dev` → include
// [dev-dependencies] in the resolved graph).
//
// AllowOutOfSync controls whether cargo refuses to mutate Cargo.lock during
// resolution. False (default) maps to `--locked`, which fails fast if the
// lockfile is stale relative to Cargo.toml — matching the
// `--strict-out-of-sync` default. True drops `--locked`, allowing cargo to
// update the lockfile to satisfy the resolve.
type cargoTreeOpts struct {
	Pkg            string
	IncludeDev     bool
	AllowOutOfSync bool
}

// cargoRunner runs `cargo tree` and `cargo metadata` on behalf of the cargo
// plugin. The two methods are grouped on a single interface because the
// production implementation is one cargo binary; splitting them would buy
// nothing test-wise and complicate the Plugin's executor wiring.
type cargoRunner interface {
	// RunTree invokes `cargo tree` in dir with the given options.
	RunTree(ctx context.Context, dir string, opts cargoTreeOpts) (io.ReadCloser, error)

	// RunMetadata invokes `cargo metadata --no-deps --format-version=1` in dir.
	// Used to enumerate workspace members and their manifest paths.
	RunMetadata(ctx context.Context, dir string) (io.ReadCloser, error)
}

// cargoCmdExecutor is the production implementation that shells out to cargo.
type cargoCmdExecutor struct{}

var _ cargoRunner = (*cargoCmdExecutor)(nil)

// buildTreeArgs constructs the `cargo tree` argument list for the given
// options. The base args are fixed:
//
//	--locked          (default): determinism + strict-out-of-sync. Dropped
//	                  when opts.AllowOutOfSync is true.
//	--all-features    (always): maximalist feature gate enablement so we see
//	                  every optional dep that could be present at build time.
//	--target=all      (always): include every cfg() target's deps regardless
//	                  of host platform.
//	--edges=normal,build[,dev]: dev added when opts.IncludeDev is true.
//	--prefix=depth, --no-dedupe, --format={p}: shape the output for the parser.
//
// We deliberately omit --offline. The unified-scanners ethos requires one
// command that runs identically in CLI (warm cache) and SCM (cold cache,
// cargo fetches on demand). --offline would force two code paths.
func buildTreeArgs(opts cargoTreeOpts) []string {
	edges := "normal,build"
	if opts.IncludeDev {
		edges = "normal,build,dev"
	}

	args := []string{"tree"}

	if !opts.AllowOutOfSync {
		args = append(args, "--locked")
	}

	args = append(args,
		"--all-features",
		"--target=all",
		"--edges="+edges,
		"--prefix=depth",
		"--no-dedupe",
		"--format={p}",
	)

	if opts.Pkg != "" {
		args = append(args, "-p", opts.Pkg)
	}

	return args
}

// baseMetadataArgs invokes cargo metadata. --no-deps keeps the JSON to just
// the workspace's own packages (no resolved transitive graph), which is all
// we need for member enumeration and bounds memory at any project size.
// --locked matches the strictness applied to cargo tree by default; member
// enumeration should fail rather than silently regenerate Cargo.lock.
var baseMetadataArgs = []string{
	"metadata",
	"--no-deps",
	"--format-version=1",
	"--locked",
}

// RunTree starts `cargo tree` and returns a streaming reader over its stdout.
// Caller must close the returned ReadCloser when done.
func (e *cargoCmdExecutor) RunTree(ctx context.Context, dir string, opts cargoTreeOpts) (io.ReadCloser, error) {
	return e.run(ctx, dir, buildTreeArgs(opts), "cargo tree")
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
