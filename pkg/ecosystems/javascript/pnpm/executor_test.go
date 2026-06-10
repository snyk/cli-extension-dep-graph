package pnpm

import "testing"

func TestParsePnpmVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "bare", raw: "8.15.8", want: "v8.15.8"},
		{name: "trailing newline", raw: "9.1.0\n", want: "v9.1.0"},
		{name: "v-prefixed", raw: "v8.6.0", want: "v8.6.0"},
		{name: "prerelease suffix", raw: "9.0.0-alpha.1", want: "v9.0.0"},
		{name: "build metadata", raw: "8.15.8+build.7", want: "v8.15.8"},
		{name: "embedded", raw: "pnpm version 8.15.8 (homebrew)", want: "v8.15.8"},
		{name: "unparseable", raw: "not-a-version", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePnpmVersion(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePnpmVersion(%q) = %q, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePnpmVersion(%q) unexpected error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("parsePnpmVersion(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
