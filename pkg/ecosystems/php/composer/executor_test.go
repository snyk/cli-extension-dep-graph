package composer

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseComposerVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "composer 2 release banner",
			raw:  "Composer version 2.7.6 2024-05-04 23:03:15",
			want: "v2.7.6",
		},
		{
			name: "bare semver",
			raw:  "2.6.0",
			want: "v2.6.0",
		},
		{
			name: "with newline",
			raw:  "Composer version 2.5.1 2022-12-22 15:33:54\n",
			want: "v2.5.1",
		},
		{
			name: "prerelease suffix",
			raw:  "Composer version 2.8.0-RC1 2024-09-01 12:00:00",
			want: "v2.8.0",
		},
		{
			name:    "completely unparseable",
			raw:     "not-a-version",
			wantErr: true,
		},
		{
			name:    "empty string",
			raw:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseComposerVersion(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestComposerArgs(t *testing.T) {
	tests := []struct {
		name string
		opts RunOptions
		want []string
	}{
		{
			name: "default excludes dev",
			opts: RunOptions{},
			want: []string{"show", "--locked", "--tree", "--no-interaction", "--no-ansi", "--no-dev"},
		},
		{
			name: "include dev drops --no-dev",
			opts: RunOptions{IncludeDev: true},
			want: []string{"show", "--locked", "--tree", "--no-interaction", "--no-ansi"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, composerArgs(tt.opts))
		})
	}
}

func TestComposerEnv_ForcesNetworkDisabled(t *testing.T) {
	// Set a conflicting parent value to prove we override, not append.
	t.Setenv("COMPOSER_DISABLE_NETWORK", "0")

	env := composerEnv()

	// Last write wins under POSIX shells, but for belt-and-braces we also
	// verify there is no stale `=0` entry left behind.
	var count, lastIdx int
	for i, kv := range env {
		if strings.HasPrefix(kv, "COMPOSER_DISABLE_NETWORK=") {
			count++
			lastIdx = i
		}
	}
	require.Equal(t, 1, count, "exactly one COMPOSER_DISABLE_NETWORK entry expected")
	assert.Equal(t, "COMPOSER_DISABLE_NETWORK=1", env[lastIdx])
}

func TestComposerEnv_InheritsParentEnv(t *testing.T) {
	t.Setenv("SOME_OTHER_VAR", "hello")

	env := composerEnv()

	// Parent env vars unrelated to COMPOSER_DISABLE_NETWORK pass through.
	found := false
	for _, kv := range env {
		if kv == "SOME_OTHER_VAR=hello" {
			found = true
			break
		}
	}
	assert.True(t, found, "parent env var should pass through")

	// And the OS environment itself should remain unchanged.
	assert.Equal(t, "hello", os.Getenv("SOME_OTHER_VAR"))
}
