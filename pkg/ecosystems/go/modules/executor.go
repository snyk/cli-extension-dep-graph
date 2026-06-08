package modules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// errGoNotFound is returned when the `go` binary is not in PATH.
var errGoNotFound = errors.New("go binary not found in PATH")

// RunOptions configure a single `go list` invocation.
//
// AdditionalArgs are inserted between `go list` and the JSON-output
// flags so callers can pass build-tag-affecting switches such as
// `-mod=vendor` or `-tags=foo,bar`. They are NOT a free-form escape
// hatch for changing the output shape — passing `-json` here will
// produce duplicate flags and fail.
//
// The output mode is always `-json -deps ./...`; that's the legacy
// snyk-go-plugin invocation and the only one we currently parse.
type RunOptions struct {
	AdditionalArgs []string
}

// goListRunner runs `go list -json -deps ./...` on behalf of the
// plugin and returns a reader over the concatenated JSON-object stream
// on stdout.
type goListRunner interface {
	Run(ctx context.Context, dir string, opts RunOptions) (io.ReadCloser, error)
}

// goCmdExecutor is the production implementation that shells out to `go`.
type goCmdExecutor struct{}

var _ goListRunner = (*goCmdExecutor)(nil)

// Run invokes `go list -json -deps ./...` with `GOPROXY=off` to enforce
// offline-only, install-free resolution: if anything is missing from
// the local module cache the command fails fast rather than silently
// fetching from the network.
//
// Other env-var contracts:
//   - GOFLAGS is cleared so we don't inherit a hostile `-mod=mod`
//     setting from the user's shell that would re-enable downloads.
//   - GOSUMDB=off avoids checksum-DB lookups that could otherwise hit
//     the network even with GOPROXY=off (rare but documented).
//   - The user's PATH and other env are preserved.
//
// Returns a buffered ReadCloser so the caller doesn't need to keep the
// subprocess alive while decoding. The `go list` JSON stream is well
// under the size that justifies io.Pipe streaming (a few MB at most
// for very large monorepos).
func (e *goCmdExecutor) Run(ctx context.Context, dir string, opts RunOptions) (io.ReadCloser, error) {
	resolved, err := exec.LookPath("go")
	if err != nil {
		return nil, errGoNotFound //nolint:wrapcheck // sentinel error, intentionally returned unwrapped
	}

	args := []string{"list"}
	args = append(args, opts.AdditionalArgs...)
	args = append(args, "-json", "-deps", "./...")

	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Dir = dir
	cmd.Env = goListEnv(os.Environ())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// `go list` can write a partial stream to stdout before
		// erroring; we surface stderr to the caller so the user has
		// something actionable (typical failure: missing module in
		// cache with GOPROXY=off).
		return nil, fmt.Errorf("go list failed: %w\nstderr: %s", err, stderr.String())
	}

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("go list produced no output\nstderr: %s", stderr.String())
	}

	return io.NopCloser(bytes.NewReader(stdout.Bytes())), nil
}

// goListEnv returns the env slice the `go list` subprocess should run
// with: the parent env with GOPROXY/GOSUMDB/GOFLAGS overridden to
// enforce offline-only resolution. Existing values for those keys are
// replaced, not augmented.
func goListEnv(parent []string) []string {
	overrides := map[string]string{
		"GOPROXY": "off",
		"GOSUMDB": "off",
		"GOFLAGS": "",
	}

	out := make([]string, 0, len(parent)+len(overrides))
	for _, kv := range parent {
		key := envKey(kv)
		if _, ok := overrides[key]; ok {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

// envKey returns the key part of a "KEY=VALUE" env entry (or the whole
// string if there's no '=').
func envKey(kv string) string {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i]
		}
	}
	return kv
}
