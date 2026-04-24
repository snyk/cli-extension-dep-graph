//go:build !integration
// +build !integration

package pip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func ptr(s string) *string { return &s }

func TestGetProjectName(t *testing.T) {
	tests := map[string]struct {
		filePath string
		scanDir  string
		override *string
		expected string
	}{
		"override_takes_precedence": {
			filePath: "project/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: ptr("custom-name"),
			expected: "custom-name",
		},
		"empty_override_is_ignored": {
			filePath: "project/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: ptr(""),
			expected: "project",
		},
		"nil_override_uses_directory": {
			filePath: "project/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: nil,
			expected: "project",
		},
		"nested_path_uses_immediate_parent": {
			filePath: "project/test/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: nil,
			expected: "test",
		},
		"root_file_falls_back_to_scan_dir": {
			filePath: "requirements.txt",
			scanDir:  "/path/to/myproject",
			override: nil,
			expected: "myproject",
		},
		"deeply_nested_uses_immediate_parent": {
			filePath: "a/b/c/d/requirements.txt",
			scanDir:  "/path/to/scandir",
			override: nil,
			expected: "d",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			result := GetProjectName(tt.filePath, tt.scanDir, tt.override)
			assert.Equal(t, tt.expected, result)
		})
	}
}
