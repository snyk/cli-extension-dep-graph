//go:build !integration
// +build !integration

package poetry

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePoetryVersion(t *testing.T) {
	cases := map[string]struct {
		raw           string
		wantMajor     int
		wantMinor     int
		wantPatch     int
		wantErrSubstr string
	}{
		"canonical_output":      {raw: "Poetry (version 1.7.1)", wantMajor: 1, wantMinor: 7, wantPatch: 1},
		"bare_semver":           {raw: "1.5.0", wantMajor: 1, wantMinor: 5, wantPatch: 0},
		"v2_canonical":          {raw: "Poetry (version 2.1.4)", wantMajor: 2, wantMinor: 1, wantPatch: 4},
		"trailing_metadata":     {raw: "Poetry (version 1.8.3-dev)", wantMajor: 1, wantMinor: 8, wantPatch: 3},
		"noisy_preamble":        {raw: "Skipping virtualenv creation\nPoetry (version 1.6.0)", wantMajor: 1, wantMinor: 6, wantPatch: 0},
		"missing_version_fails": {raw: "Poetry — no version printed", wantErrSubstr: "could not parse poetry version"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			major, minor, patch, err := parsePoetryVersion(tc.raw)
			if tc.wantErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantMajor, major)
			assert.Equal(t, tc.wantMinor, minor)
			assert.Equal(t, tc.wantPatch, patch)
		})
	}
}

func TestSentinelErrorsAreSurfaced(t *testing.T) {
	// Defence-in-depth: these are exported (lowercase) sentinels the
	// plugin wraps for user-facing messages. Make sure the wrappers
	// preserve errors.Is for both.
	wrapped := (&Plugin{}).wrapRunError(errPoetryNotFound)
	assert.True(t, errors.Is(wrapped, errPoetryNotFound))
	assert.Contains(t, wrapped.Error(), "not installed")

	wrapped = (&Plugin{}).wrapRunError(errPoetryVersionTooLow)
	assert.True(t, errors.Is(wrapped, errPoetryVersionTooLow))
	assert.Contains(t, wrapped.Error(), "is required")
}
