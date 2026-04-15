package bun

import (
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
