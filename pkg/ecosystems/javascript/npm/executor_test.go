package npm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNpmVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "bare semver",
			raw:  "10.5.0",
			want: "v10.5.0",
		},
		{
			name: "with newline",
			raw:  "10.5.0\n",
			want: "v10.5.0",
		},
		{
			name: "npm 6 release",
			raw:  "6.14.18",
			want: "v6.14.18",
		},
		{
			name: "prerelease suffix",
			raw:  "11.0.0-beta.1",
			want: "v11.0.0",
		},
		{
			name: "noisy preamble",
			raw:  "npm 10.5.0",
			want: "v10.5.0",
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
			got, err := parseNpmVersion(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRunOptions_OmitFlags(t *testing.T) {
	tests := []struct {
		name string
		opts RunOptions
		want []string
	}{
		{name: "zero value emits nothing", opts: RunOptions{}, want: nil},
		{name: "OmitDev", opts: RunOptions{OmitDev: true}, want: []string{"--omit=dev"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.opts.omitFlags())
		})
	}
}
