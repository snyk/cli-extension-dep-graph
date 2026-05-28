package bazel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/require"
)

func Test_createGoLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		goMod    string
		expected goLookup
	}{
		{
			name: "basic requires map to gazelle repo names with normalized versions",
			goMod: `module example.com/app

go 1.22

require (
	github.com/spf13/cobra v1.8.0
	golang.org/x/text v0.14.0
	gopkg.in/yaml.v3 v3.0.1
)
`,
			expected: goLookup{
				"com_github_spf13_cobra": {Name: "github.com/spf13/cobra", Version: "1.8.0"},
				"org_golang_x_text":      {Name: "golang.org/x/text", Version: "0.14.0"},
				"in_gopkg_yaml_v3":       {Name: "gopkg.in/yaml.v3", Version: "3.0.1"},
			},
		},
		{
			name: "pseudo-version is reduced to short sha",
			goMod: `module example.com/app

go 1.22

require github.com/bazelbuild/buildtools v0.0.0-20250930140053-2eb4fccefb52
`,
			expected: goLookup{
				"com_github_bazelbuild_buildtools": {Name: "github.com/bazelbuild/buildtools", Version: "#2eb4fccefb52"},
			},
		},
		{
			name: "versioned replace points at replacement coordinate, keyed by original repo",
			goMod: `module example.com/app

go 1.22

require github.com/foo/bar v1.0.0

replace github.com/foo/bar => github.com/myorg/bar v1.0.0-fork
`,
			expected: goLookup{
				"com_github_foo_bar": {Name: "github.com/myorg/bar", Version: "1.0.0-fork"},
			},
		},
		{
			name: "local-path replace falls back to original require entry",
			goMod: `module example.com/app

go 1.22

require github.com/foo/bar v1.0.0

replace github.com/foo/bar => ../local/bar
`,
			expected: goLookup{
				"com_github_foo_bar": {Name: "github.com/foo/bar", Version: "1.0.0"},
			},
		},
		{
			name: "no requires yields empty lookup",
			goMod: `module example.com/app

go 1.22
`,
			expected: goLookup{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "go.mod")
			require.NoError(t, os.WriteFile(path, []byte(tt.goMod), 0o600))

			actual, err := createGoLookup(path)
			require.NoError(t, err)
			require.Equal(t, tt.expected, actual)
		})
	}
}

func Test_createGoLookup_FileNotFound(t *testing.T) {
	t.Parallel()

	_, err := createGoLookup(filepath.Join(t.TempDir(), "missing.mod"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "required file does not exist")
}

func Test_createGoLookup_InvalidContent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "go.mod")
	require.NoError(t, os.WriteFile(path, []byte("this is not a go.mod"), 0o600))

	_, err := createGoLookup(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse")
}

func Test_goResolver_labelToPkgInfo(t *testing.T) {
	t.Parallel()

	r := &goResolver{
		lookup: goLookup{
			"com_github_spf13_cobra":           {Name: "github.com/spf13/cobra", Version: "1.8.0"},
			"org_golang_x_text":                {Name: "golang.org/x/text", Version: "0.14.0"},
			"com_github_bazelbuild_buildtools": {Name: "github.com/bazelbuild/buildtools", Version: "#2eb4fccefb52"},
		},
	}

	tests := []struct {
		name     string
		label    string
		expected depgraph.PkgInfo
	}{
		{
			name:     "module-root label resolves to module import path",
			label:    "@com_github_spf13_cobra//:cobra",
			expected: depgraph.PkgInfo{Name: "github.com/spf13/cobra", Version: "1.8.0"},
		},
		{
			name:     "subpackage label appends pkg path to module",
			label:    "@com_github_spf13_cobra//doc:doc",
			expected: depgraph.PkgInfo{Name: "github.com/spf13/cobra/doc", Version: "1.8.0"},
		},
		{
			name:     "nested subpackage path is fully preserved",
			label:    "@org_golang_x_text//unicode/norm:norm",
			expected: depgraph.PkgInfo{Name: "golang.org/x/text/unicode/norm", Version: "0.14.0"},
		},
		{
			name:     "pseudo-version coordinate flows through to pkg info",
			label:    "@com_github_bazelbuild_buildtools//build:build",
			expected: depgraph.PkgInfo{Name: "github.com/bazelbuild/buildtools/build", Version: "#2eb4fccefb52"},
		},
		{
			name:     "bzlmod canonical label with ~ separators resolves via apparent name",
			label:    "@@rules_go~~go_deps~com_github_spf13_cobra//cobra:cobra",
			expected: depgraph.PkgInfo{Name: "github.com/spf13/cobra/cobra", Version: "1.8.0"},
		},
		{
			name:     "bzlmod canonical label with + separators resolves via apparent name",
			label:    "@@rules_go++go_deps+com_github_spf13_cobra//doc:doc",
			expected: depgraph.PkgInfo{Name: "github.com/spf13/cobra/doc", Version: "1.8.0"},
		},
		{
			name:     "unknown external repo falls back to raw label",
			label:    "@com_github_unknown_pkg//foo:bar",
			expected: depgraph.PkgInfo{Name: "@com_github_unknown_pkg//foo:bar"},
		},
		{
			name:     "first-party label is preserved verbatim",
			label:    "//pkg/internal:foo",
			expected: depgraph.PkgInfo{Name: "//pkg/internal:foo"},
		},
		{
			name:     "empty label is preserved verbatim",
			label:    "",
			expected: depgraph.PkgInfo{Name: ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, &tt.expected, r.labelToPkgInfo(tt.label))
		})
	}
}

func Test_normalizeVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty stays empty", input: "", expected: ""},
		{name: "semver strips leading v", input: "v1.2.3", expected: "1.2.3"},
		{name: "semver without v is unchanged", input: "1.2.3", expected: "1.2.3"},
		{name: "semver with pre-release tag retains suffix", input: "v1.0.0-fork", expected: "1.0.0-fork"},
		{name: "semver with build metadata retains suffix", input: "v1.2.3+build.5", expected: "1.2.3+build.5"},
		{name: "major version v2 strips leading v", input: "v2.0.0", expected: "2.0.0"},
		{
			name:     "pseudo-version with zero base reduces to short sha",
			input:    "v0.0.0-20250930140053-2eb4fccefb52",
			expected: "#2eb4fccefb52",
		},
		{
			name:     "pseudo-version with pre-release base reduces to short sha",
			input:    "v1.2.3-0.20240101120000-abcdef123456",
			expected: "#abcdef123456",
		},
		{
			name:     "pseudo-version with bumped patch base reduces to short sha",
			input:    "v0.1.1-0.20240101120000-abcdef123456",
			expected: "#abcdef123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expected, normalizeVersion(tt.input))
		})
	}
}
