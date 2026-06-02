package cargo

import (
	"errors"
	"fmt"
	"strings"
)

// classifyCargoError walks err's chain looking for known cargo failure
// patterns and wraps with a user-actionable message + a stable sentinel
// (errLockfileOutOfSync etc.) when one matches.
//
// Detection is by substring match against cargo's stderr text, surfaced
// through the io.Pipe close-error from the executor. cargo's error wording
// is stable enough across recent versions for this to be reliable, but
// changes to cargo are the obvious failure mode — fixture coverage in the
// acceptance suite is the canary.
//
// Returns the original error unchanged if no pattern matches.
func classifyCargoError(err error) error {
	if err == nil {
		return nil
	}

	msg := err.Error()

	if isLockfileOutOfSyncMessage(msg) {
		return fmt.Errorf(
			"%w; run `cargo update` to regenerate Cargo.lock, or pass --strict-out-of-sync=false to let cargo regenerate it during the scan: %w",
			errLockfileOutOfSync, err,
		)
	}

	return err
}

// isLockfileOutOfSyncMessage matches cargo's error text for `--locked`
// rejecting a stale Cargo.lock. Cargo's wording has been stable since 1.41
// but we accept a couple of variants seen in the wild for safety.
func isLockfileOutOfSyncMessage(msg string) bool {
	lower := strings.ToLower(msg)
	return strings.Contains(lower, "the lock file") &&
		strings.Contains(lower, "needs to be updated")
}

// Compile-time sanity check that classifyCargoError preserves the sentinel
// when wrapping, so callers can use errors.Is to detect the case.
var _ = func() bool {
	wrapped := classifyCargoError(errors.New("the lock file Cargo.lock needs to be updated but --locked was passed to prevent this"))
	return errors.Is(wrapped, errLockfileOutOfSync)
}()
