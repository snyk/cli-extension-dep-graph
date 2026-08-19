package orchestrator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// GetAllFlags is what downstream consumers read to register these feature
// flags with the flag service. A resolver missing from it is never gated per
// org — its config key simply stays false everywhere — so every flag the
// registry checks must appear here.
func TestGetAllFlags_ExposesEveryRegisteredFlag(t *testing.T) {
	flags := GetAllFlags()

	for _, f := range allFlags {
		assert.Equal(t, f.Value, flags[f.Key], "flag %q should be exposed for org-level registration", f.Key)
	}

	assert.Len(t, flags, len(allFlags), "no flag should be dropped by key collision")
	assert.Contains(t, flags, FlagDotnetResolver.Key)
}
