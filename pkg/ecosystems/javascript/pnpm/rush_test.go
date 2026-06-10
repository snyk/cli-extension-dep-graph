package pnpm

import (
	"strings"
	"testing"
)

func TestStripJSONComments(t *testing.T) {
	tests := []struct {
		name           string
		in             string
		mustNotContain []string
		mustContain    []string
	}{
		{
			name:           "block comment removed",
			in:             `{ /* "pnpmVersion": "7.0.0", */ "npmVersion": "9.0.0" }`,
			mustNotContain: []string{"pnpmVersion"},
			mustContain:    []string{"npmVersion"},
		},
		{
			name:           "whole-line comment removed",
			in:             "{\n  // \"pnpmVersion\": \"7.0.0\",\n  \"npmVersion\": \"9.0.0\"\n}",
			mustNotContain: []string{"pnpmVersion"},
			mustContain:    []string{"npmVersion"},
		},
		{
			name:        "inline // inside a string value is preserved",
			in:          "{\n  \"$schema\": \"https://example.com/v5/rush.schema.json\",\n  \"pnpmVersion\": \"8.15.8\"\n}",
			mustContain: []string{"https://example.com", "pnpmVersion"},
		},
		{
			name:        "real config untouched",
			in:          "{\n  \"pnpmVersion\": \"8.15.8\",\n  \"projects\": [{ \"projectFolder\": \"apps/a\" }]\n}",
			mustContain: []string{"pnpmVersion", "apps/a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(stripJSONComments([]byte(tt.in)))
			for _, s := range tt.mustNotContain {
				if strings.Contains(got, s) {
					t.Errorf("stripped output should not contain %q; got:\n%s", s, got)
				}
			}
			for _, s := range tt.mustContain {
				if !strings.Contains(got, s) {
					t.Errorf("stripped output should contain %q; got:\n%s", s, got)
				}
			}
		})
	}
}
