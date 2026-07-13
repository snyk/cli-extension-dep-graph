package bazel

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// debugLogger writes to stderr so a bazel command failure inside
// buildDepGraph (logged and skipped per-target, not returned as an error —
// see plugin.go) is visible in test output instead of silently producing an
// empty result set. Error (and Info) messages always show; set
// BAZEL_INTEGRATION_TEST_DEBUG=1 to additionally surface the noisier
// per-target Debug logs (e.g. "found bazel targets") for deeper diagnostics.
func debugLogger() logger.Logger {
	level := slog.LevelInfo
	if os.Getenv("BAZEL_INTEGRATION_TEST_DEBUG") == "1" {
		level = slog.LevelDebug
	}
	return logger.NewFromSlog(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

// bazelShutdown kills the persistent bazel server for dir before switching
// --bazel-platforms between subtests against the same fixture. Reusing a
// server across a --platforms change makes bazel discard and rebuild its
// analysis cache in place, which briefly holds both the old and new
// analysis state in memory; under a constrained CI runner this has been
// observed to crash the server outright ("Server terminated abruptly ...
// Socket closed"), which buildDepGraph then reports as a per-target error
// (logged and skipped, not fatal — see plugin.go), silently producing an
// empty result. Starting each platform variant from a clean server avoids
// the transient double-state memory spike.
func bazelShutdown(t *testing.T, dir string) {
	t.Helper()
	// Bounded independently of the test's own context: this must never be
	// able to hang the whole test run (e.g. on a stalled bazelisk fetch) the
	// way a plain exec.Command could.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bazel", "shutdown")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("bazel shutdown (non-fatal): %v: %s", err, out)
	}
}

// snapshotResults wraps results in the shape JSON snapshot tests
// compare against. ProcessedFiles is asserted by tests that care
// (assertGoProcessedFiles, etc.); the snapshot keeps an empty list
// so host-specific paths don't leak into the golden file.
func snapshotResults(results []ecosystems.SCAResult) any {
	cleaned := make([]ecosystems.SCAResult, len(results))
	copy(cleaned, results)
	for i := range cleaned {
		cleaned[i].ProcessedFiles = nil
	}
	return struct {
		Results        []ecosystems.SCAResult `json:"results"`
		ProcessedFiles []string               `json:"processedFiles"`
	}{
		Results:        cleaned,
		ProcessedFiles: []string{},
	}
}
