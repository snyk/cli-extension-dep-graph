package swiftpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSwiftVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{
			name: "apple swift full",
			raw:  "swift-driver version: 1.84.1 Apple Swift version 5.9.2 (swiftlang-5.9.2.2.56 clang-1500.1.0.2.5)\nTarget: arm64-apple-macosx14.0",
			want: "v5.9.2",
		},
		{
			name: "apple swift modern",
			raw:  "swift-driver version: 1.148.6 Apple Swift version 6.3.2 (swiftlang-6.3.2.1.108 clang-2100.1.1.101)\nTarget: arm64-apple-macosx26.0",
			want: "v6.3.2",
		},
		{
			name: "linux swift",
			raw:  "Swift version 5.7.3 (swift-5.7.3-RELEASE)\nTarget: x86_64-unknown-linux-gnu",
			want: "v5.7.3",
		},
		{
			name: "minimum supported",
			raw:  "Apple Swift version 5.6",
			want: "v5.6.0",
		},
		{
			name: "swift 5.10",
			raw:  "Apple Swift version 5.10.1",
			want: "v5.10.1",
		},
		{
			name:    "no swift version marker",
			raw:     "swift-driver version: 1.84.1",
			wantErr: true,
		},
		{
			name:    "empty string",
			raw:     "",
			wantErr: true,
		},
		{
			name:    "completely unparseable",
			raw:     "not-a-version",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSwiftVersion(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
