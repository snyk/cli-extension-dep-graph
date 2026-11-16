package bun

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBunVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "bare semver",
			raw:  "1.2.19",
			want: "v1.2.19",
		},
		{
			name: "with newline",
			raw:  "1.2.19\n",
			want: "v1.2.19",
		},
		{
			name: "canary suffix",
			raw:  "1.3.0-canary.123",
			want: "v1.3.0",
		},
		{
			name: "build metadata",
			raw:  "1.3.0+build.456",
			want: "v1.3.0",
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
			got, err := parseBunVersion(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckBunVersionHidesSnykVariablesFromChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake bun binary is a POSIX shell script")
	}
	t.Setenv("SNYK_TOKEN", "secret")
	dir := t.TempDir()
	envFile := filepath.Join(dir, "child-env.txt")
	script := filepath.Join(dir, "bun")
	body := "#!/bin/sh\nenv > '" + envFile + "'\necho 1.2.19\n"
	require.NoError(t, os.WriteFile(script, []byte(body), 0o755)) //nolint:gosec // the fake binary must be executable

	require.NoError(t, checkBunVersion(context.Background(), script))

	childEnv, err := os.ReadFile(envFile)
	require.NoError(t, err)
	var names []string
	for _, line := range strings.Split(string(childEnv), "\n") {
		if name, _, found := strings.Cut(line, "="); found {
			names = append(names, name)
		}
	}
	require.NotEmpty(t, names)
	assert.NotContains(t, names, "SNYK_TOKEN")
}
