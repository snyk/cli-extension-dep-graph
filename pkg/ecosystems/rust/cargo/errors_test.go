package cargo

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyCargoError_LockfileOutOfSync(t *testing.T) {
	// Cargo's actual stderr text from --locked rejecting a stale lockfile.
	cargoErr := errors.New("error: the lock file Cargo.lock needs to be updated but --locked was passed to prevent this")

	got := classifyCargoError(cargoErr)
	require.Error(t, got)

	// User-facing message names the failure mode.
	assert.Contains(t, got.Error(), "out of sync")
	// And hints at the actionable fix.
	assert.Contains(t, got.Error(), "--strict-out-of-sync=false")

	// Sentinel is reachable via errors.Is so callers can detect this case.
	assert.True(t, errors.Is(got, errLockfileOutOfSync))
	// Original error is preserved in the chain.
	assert.True(t, errors.Is(got, cargoErr))
}

func TestClassifyCargoError_LockfileOutOfSync_NestedWrapping(t *testing.T) {
	// Real-world path: the cargo error comes back wrapped through the
	// pipe-close-error → parseTree → buildMemberResult chain. Classification
	// must still match.
	inner := errors.New("cargo tree failed: exit status 101\nstderr: error: the lock file Cargo.lock needs to be updated but --locked was passed to prevent this")
	wrapped := fmt.Errorf("parsing cargo tree output for member my-app: scanning cargo tree output: %w", inner)

	got := classifyCargoError(wrapped)
	require.Error(t, got)
	assert.True(t, errors.Is(got, errLockfileOutOfSync))
}

func TestClassifyCargoError_PassesThroughUnknown(t *testing.T) {
	// Errors we don't recognize pass through unchanged.
	original := errors.New("some unfamiliar cargo failure")
	got := classifyCargoError(original)
	assert.Equal(t, original, got)
}

func TestClassifyCargoError_NilPassesThrough(t *testing.T) {
	assert.NoError(t, classifyCargoError(nil))
}
