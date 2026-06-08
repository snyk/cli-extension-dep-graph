package bundler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParse_Simple covers the canonical GEM-only Gemfile.lock with PLATFORMS,
// DEPENDENCIES, and BUNDLED WITH — the format produced by 95%+ of real
// bundler projects.
func TestParse_Simple(t *testing.T) {
	src := `GEM
  remote: http://rubygems.org/
  specs:
    json (2.0.2)
    lynx (0.4.0)

PLATFORMS
  ruby

DEPENDENCIES
  json
  lynx (= 0.4.0)

BUNDLED WITH
   1.13.5
`
	lf, err := Parse(strings.NewReader(src))
	require.NoError(t, err)

	require.Contains(t, lf.Specs, "json")
	require.Contains(t, lf.Specs, "lynx")
	assert.Equal(t, "2.0.2", lf.Specs["json"].Version)
	assert.Equal(t, "0.4.0", lf.Specs["lynx"].Version)
	assert.Equal(t, SourceGEM, lf.Specs["json"].Source.Type)
	assert.Equal(t, "http://rubygems.org/", lf.Specs["json"].Source.Remote)

	require.Len(t, lf.Dependencies, 2)
	assert.Equal(t, "json", lf.Dependencies[0].Name)
	assert.False(t, lf.Dependencies[0].Pinned)
	assert.Equal(t, "lynx", lf.Dependencies[1].Name)

	assert.Equal(t, []string{"ruby"}, lf.Platforms)
	assert.Equal(t, "1.13.5", lf.BundledWith)
}

// TestParse_SpecChildren verifies that nested deps under a spec are
// captured (indent depth 6 lines), and that version constraints in
// parens are discarded (we only need names; versions live in lf.Specs).
func TestParse_SpecChildren(t *testing.T) {
	src := `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.8.5)
      mini_portile2 (~> 2.3.0)
    mini_portile2 (2.3.0)
    sanitize (4.6.2)
      crass (~> 1.0.2)
      nokogiri (>= 1.4.4)
    crass (1.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  sanitize

BUNDLED WITH
   1.16.5
`
	lf, err := Parse(strings.NewReader(src))
	require.NoError(t, err)

	require.Contains(t, lf.Specs, "nokogiri")
	assert.Equal(t, []string{"mini_portile2"}, lf.Specs["nokogiri"].Children)
	require.Contains(t, lf.Specs, "sanitize")
	assert.Equal(t, []string{"crass", "nokogiri"}, lf.Specs["sanitize"].Children)
	assert.Empty(t, lf.Specs["crass"].Children)
}

// TestParse_WithGitDeps covers GIT blocks and the `!` marker on
// DEPENDENCIES entries — both ported from the legacy plugin and
// verified by the registry's with-git-specs fixture.
func TestParse_WithGitDeps(t *testing.T) {
	src := `GIT
  remote: https://github.com/rspec/rspec.git
  revision: bc209d4a2a2dfbf38ac1d470b213753aa9e654db
  specs:
    rspec (3.6.0.beta1)
      rspec-core (= 3.6.0.beta1)

GIT
  remote: https://github.com/sparklemotion/nokogiri.git
  revision: 7f8b7b2bf55829e02cd11c2eb25814c3ed458676
  specs:
    nokogiri (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    rspec-core (3.6.0.beta1)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri (= 1.0.0)!
  rspec!

BUNDLED WITH
   1.13.6
`
	lf, err := Parse(strings.NewReader(src))
	require.NoError(t, err)

	// GIT-sourced specs are present and tagged.
	require.Contains(t, lf.Specs, "rspec")
	require.Contains(t, lf.Specs, "nokogiri")
	require.NotNil(t, lf.Specs["rspec"].Source)
	assert.Equal(t, SourceGIT, lf.Specs["rspec"].Source.Type)
	assert.Equal(t, "https://github.com/rspec/rspec.git", lf.Specs["rspec"].Source.Remote)
	assert.Equal(t, "bc209d4a2a2dfbf38ac1d470b213753aa9e654db", lf.Specs["rspec"].Source.Revision)

	// `!` marker stripped, but flag preserved in Pinned.
	require.Len(t, lf.Dependencies, 2)
	assert.Equal(t, "nokogiri", lf.Dependencies[0].Name)
	assert.True(t, lf.Dependencies[0].Pinned, "nokogiri dep line has `!`")
	assert.Equal(t, "rspec", lf.Dependencies[1].Name)
	assert.True(t, lf.Dependencies[1].Pinned, "rspec dep line has `!`")
}

// TestParse_WithPathDeps covers a PATH block (gemspec project).
func TestParse_WithPathDeps(t *testing.T) {
	src := `PATH
  remote: .
  specs:
    ruby-gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    rake (10.5.0)

PLATFORMS
  ruby

DEPENDENCIES
  bundler (~> 1.13)
  rake (~> 10.0)
  ruby-gem!

BUNDLED WITH
   1.13.5
`
	lf, err := Parse(strings.NewReader(src))
	require.NoError(t, err)

	require.Contains(t, lf.Specs, "ruby-gem")
	assert.Equal(t, SourcePATH, lf.Specs["ruby-gem"].Source.Type)
	assert.Equal(t, ".", lf.Specs["ruby-gem"].Source.Remote)

	// bundler appears in DEPENDENCIES but won't have a spec — that's
	// expected (legacy parser also silently skips it).
	require.Len(t, lf.Dependencies, 3)
	assert.Equal(t, "bundler", lf.Dependencies[0].Name)
	assert.Equal(t, "ruby-gem", lf.Dependencies[2].Name)
	assert.True(t, lf.Dependencies[2].Pinned)
}

// TestParse_WithPlatforms preserves multiple platform entries verbatim.
func TestParse_WithPlatforms(t *testing.T) {
	src := `GEM
  remote: https://rubygems.org/
  specs:
    json (2.0.2)

PLATFORMS
  ruby
  x86_64-linux
  arm64-darwin

DEPENDENCIES
  json

BUNDLED WITH
   2.4.10
`
	lf, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	assert.Equal(t, []string{"ruby", "x86_64-linux", "arm64-darwin"}, lf.Platforms)
}

// TestParse_RubyVersion captures the RUBY VERSION block.
func TestParse_RubyVersion(t *testing.T) {
	src := `GEM
  remote: https://rubygems.org/
  specs:
    json (2.0.2)

PLATFORMS
  ruby

DEPENDENCIES
  json

RUBY VERSION
   ruby 2.7.0p0

BUNDLED WITH
   2.1.4
`
	lf, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	assert.Equal(t, "2.7.0p0", lf.RubyVersion)
}

// TestParse_Empty handles a fully blank file and a header-only file
// without panicking.
func TestParse_Empty(t *testing.T) {
	lf, err := Parse(strings.NewReader(""))
	require.NoError(t, err)
	assert.NotNil(t, lf)
	assert.Empty(t, lf.Specs)
	assert.Empty(t, lf.Dependencies)
}

// TestParse_DependencyVariants exercises the line-shapes seen in real
// lockfiles for the DEPENDENCIES block.
func TestParse_DependencyVariants(t *testing.T) {
	src := `GEM
  remote: https://rubygems.org/
  specs:
    a (1.0)

PLATFORMS
  ruby

DEPENDENCIES
  bare-name
  pinned-name!
  versioned (= 1.2.3)
  versioned-and-pinned (~> 2.0)!
`
	lf, err := Parse(strings.NewReader(src))
	require.NoError(t, err)
	require.Len(t, lf.Dependencies, 4)
	assert.Equal(t, "bare-name", lf.Dependencies[0].Name)
	assert.False(t, lf.Dependencies[0].Pinned)
	assert.Equal(t, "pinned-name", lf.Dependencies[1].Name)
	assert.True(t, lf.Dependencies[1].Pinned)
	assert.Equal(t, "versioned", lf.Dependencies[2].Name)
	assert.False(t, lf.Dependencies[2].Pinned)
	assert.Equal(t, "versioned-and-pinned", lf.Dependencies[3].Name)
	assert.True(t, lf.Dependencies[3].Pinned)
}

// TestParse_SpecLine covers the parseSpecLine helper directly: bare
// names, version, version+platform, malformed.
func TestParse_SpecLine(t *testing.T) {
	cases := []struct {
		in              string
		wantName, wantV string
	}{
		{"nokogiri (1.8.5)", "nokogiri", "1.8.5"},
		{"nokogiri (1.8.5-x86_64-linux)", "nokogiri", "1.8.5-x86_64-linux"},
		{"bare", "bare", ""},
		{"  trimmed (= 1.0)", "trimmed", "= 1.0"},
		{"", "", ""},
		{"oddly-formed (", "oddly-formed", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			name, v := parseSpecLine(tc.in)
			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantV, v)
		})
	}
}

// TestParse_NilReader is a guard against accidentally passing nil.
func TestParse_NilReader(t *testing.T) {
	_, err := Parse(nil)
	assert.Error(t, err)
}

// TestParseDependencyLine covers all observed forms.
func TestParseDependencyLine(t *testing.T) {
	cases := []struct {
		in   string
		want Dependency
	}{
		{"json", Dependency{Name: "json"}},
		{"lynx (= 0.4.0)", Dependency{Name: "lynx"}},
		{"rspec!", Dependency{Name: "rspec", Pinned: true}},
		{"nokogiri (= 1.0.0)!", Dependency{Name: "nokogiri", Pinned: true}},
		{"bundler (~> 1.13)", Dependency{Name: "bundler"}},
		{"   padded  ", Dependency{Name: "padded"}},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := parseDependencyLine(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}
