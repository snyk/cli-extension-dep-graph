package cocoapods

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSpecification(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
		wantErr  bool
	}{
		{in: "Adjust (4.17.1)", wantName: "Adjust", wantVer: "4.17.1"},
		{in: "Adjust/Core (4.17.1)", wantName: "Adjust/Core", wantVer: "4.17.1"},
		{in: "Artsy+UIColors (3.1.0)", wantName: "Artsy+UIColors", wantVer: "3.1.0"},
		{in: "AFNetworking/NSURLConnection (2.5.4)", wantName: "AFNetworking/NSURLConnection", wantVer: "2.5.4"},
		{in: "Expecta (1.0.5)", wantName: "Expecta", wantVer: "1.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSpecification(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, got.Name)
			assert.Equal(t, tc.wantVer, got.Version)
		})
	}
}

func TestParseDependency(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		{in: "Expecta", wantName: "Expecta", wantVer: ""},
		{in: "ReactiveObjC (~> 2.0)", wantName: "ReactiveObjC", wantVer: "~> 2.0"},
		{in: "AFNetworking/NSURLConnection (= 2.5.4)", wantName: "AFNetworking/NSURLConnection", wantVer: "= 2.5.4"},
		{
			in:       "Pulley (from `https://github.com/l2succes/Pulley.git`, branch `master`)",
			wantName: "Pulley",
			wantVer:  "", // "from ..." clauses are dropped — there's no resolved requirement.
		},
		{
			in:       "Silica (from `https://github.com/ianyh/Silica.git`, tag `0.1.5`)",
			wantName: "Silica",
			wantVer:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseDependency(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.wantName, got.Name)
			assert.Equal(t, tc.wantVer, got.Version)
		})
	}
}

func TestRootSpecName(t *testing.T) {
	cases := map[string]string{
		"AFNetworking":                  "AFNetworking",
		"AFNetworking/NSURLConnection":  "AFNetworking",
		"React/Core":                    "React",
		"React-Native/Core/Subspec":     "React-Native",
		"Artsy+UIColors":                "Artsy+UIColors",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, RootSpecName(in))
		})
	}
}

const simpleLockfile = `PODS:
  - Reachability (3.1.0)

DEPENDENCIES:
  - Reachability (= 3.1.0)

SPEC REPOS:
  trunk:
    - Reachability

SPEC CHECKSUMS:
  Reachability: 3c8fe9643e52184d17f207e781cd84158da8c02b

COCOAPODS: 1.10.0
`

func TestParseLockfile_Simple(t *testing.T) {
	lock, err := ParseLockfile(strings.NewReader(simpleLockfile))
	require.NoError(t, err)

	require.Len(t, lock.Pods, 1)
	assert.Equal(t, "Reachability (3.1.0)", lock.Pods[0].Spec)
	assert.Empty(t, lock.Pods[0].Deps)

	assert.Equal(t, []string{"Reachability (= 3.1.0)"}, lock.Dependencies)
	assert.Equal(t, "1.10.0", lock.CocoapodsVersion)
	assert.Equal(t, "3c8fe9643e52184d17f207e781cd84158da8c02b", lock.SpecChecksums["Reachability"])
	assert.Equal(t, []string{"Reachability"}, lock.SpecRepos["trunk"])
}

const withSubspecsLockfile = `PODS:
  - AFNetworking (2.5.4):
    - AFNetworking/NSURLConnection (= 2.5.4)
    - AFNetworking/Security (= 2.5.4)
  - AFNetworking/NSURLConnection (2.5.4):
    - AFNetworking/Security
  - AFNetworking/Security (2.5.4)

DEPENDENCIES:
  - AFNetworking (~> 2.5)

SPEC CHECKSUMS:
  AFNetworking: deadbeef

COCOAPODS: 1.10.0
`

func TestParseLockfile_WithSubspecs(t *testing.T) {
	lock, err := ParseLockfile(strings.NewReader(withSubspecsLockfile))
	require.NoError(t, err)

	require.Len(t, lock.Pods, 3)
	assert.Equal(t, "AFNetworking (2.5.4)", lock.Pods[0].Spec)
	assert.Len(t, lock.Pods[0].Deps, 2, "AFNetworking has two subspec deps in the fixture")
	assert.Equal(t, "AFNetworking/NSURLConnection (= 2.5.4)", lock.Pods[0].Deps[0])

	// Bare leaf
	assert.Equal(t, "AFNetworking/Security (2.5.4)", lock.Pods[2].Spec)
	assert.Empty(t, lock.Pods[2].Deps)
}

const withExternalSourcesLockfile = `PODS:
  - Silica (0.1.5)

DEPENDENCIES:
  - Silica (from ` + "`https://github.com/ianyh/Silica.git`" + `, tag ` + "`0.1.5`" + `)

EXTERNAL SOURCES:
  Silica:
    :git: https://github.com/ianyh/Silica.git
    :tag: 0.1.5

SPEC CHECKSUMS:
  Silica: 3b5a774469476ef84fe9d96a63bfe09908654e50

COCOAPODS: 1.3.1
`

func TestParseLockfile_WithExternalSources(t *testing.T) {
	lock, err := ParseLockfile(strings.NewReader(withExternalSourcesLockfile))
	require.NoError(t, err)

	ext, ok := lock.ExternalSources["Silica"]
	require.True(t, ok, "ExternalSources[Silica] should be present")
	assert.Equal(t, "https://github.com/ianyh/Silica.git", ext.Git)
	assert.Equal(t, "0.1.5", ext.Tag)
	assert.Empty(t, ext.Branch)
}

const withCheckoutOptionsLockfile = `PODS:
  - Just (0.6.0)

DEPENDENCIES:
  - Just

EXTERNAL SOURCES:
  Just:
    :branch: swift-5
    :git: https://github.com/iina/Just

CHECKOUT OPTIONS:
  Just:
    :commit: d0ae3f9bc2d6bf247b19217764a096bbac55f007
    :git: https://github.com/iina/Just

SPEC CHECKSUMS:
  Just: abc

COCOAPODS: 1.10.0
`

func TestParseLockfile_WithCheckoutOptions(t *testing.T) {
	lock, err := ParseLockfile(strings.NewReader(withCheckoutOptionsLockfile))
	require.NoError(t, err)

	co, ok := lock.CheckoutOptions["Just"]
	require.True(t, ok)
	assert.Equal(t, "d0ae3f9bc2d6bf247b19217764a096bbac55f007", co.Commit)
	assert.Equal(t, "https://github.com/iina/Just", co.Git)
	assert.Empty(t, co.Tag)
}

// TestParseLockfile_MissingOptionalSections asserts that older lockfiles
// (no SPEC REPOS / EXTERNAL SOURCES / CHECKOUT OPTIONS / PODFILE
// CHECKSUM / COCOAPODS) parse without error and leave those fields nil
// or empty.
func TestParseLockfile_MissingOptionalSections(t *testing.T) {
	const lockfile = `PODS:
  - Foo (1.0.0)

DEPENDENCIES:
  - Foo

SPEC CHECKSUMS:
  Foo: abc
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)
	assert.Empty(t, lock.SpecRepos)
	assert.Empty(t, lock.ExternalSources)
	assert.Empty(t, lock.CheckoutOptions)
	assert.Empty(t, lock.PodfileChecksum)
	assert.Empty(t, lock.CocoapodsVersion)
}

func TestParseLockfile_PodfileChecksum(t *testing.T) {
	const lockfile = `PODS:
  - Foo (1.0.0)

DEPENDENCIES:
  - Foo

SPEC CHECKSUMS:
  Foo: abc

PODFILE CHECKSUM: 56045e819fdcab3669f1847a1bc88e6702accf51

COCOAPODS: 1.10.0
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)
	assert.Equal(t, "56045e819fdcab3669f1847a1bc88e6702accf51", lock.PodfileChecksum)
}

// TestParseLockfile_QuotedPodNames covers pod names that need to be
// quoted in YAML because they contain a "+" or other punctuation. The
// quotes themselves are stripped by the YAML decoder; the spec string
// we keep is the raw "Name (version)".
func TestParseLockfile_QuotedPodNames(t *testing.T) {
	const lockfile = `PODS:
  - "Artsy+UIColors (3.1.0)"
  - "Artsy+UIFonts (3.3.3)"

DEPENDENCIES:
  - "Artsy+UIColors"

SPEC CHECKSUMS:
  "Artsy+UIColors": abc
  "Artsy+UIFonts": def
`
	lock, err := ParseLockfile(strings.NewReader(lockfile))
	require.NoError(t, err)

	require.Len(t, lock.Pods, 2)
	assert.Equal(t, "Artsy+UIColors (3.1.0)", lock.Pods[0].Spec)

	got, err := ParseSpecification(lock.Pods[0].Spec)
	require.NoError(t, err)
	assert.Equal(t, "Artsy+UIColors", got.Name)
	assert.Equal(t, "3.1.0", got.Version)
}

func TestParseLockfile_InvalidYAML(t *testing.T) {
	_, err := ParseLockfile(strings.NewReader("this is not yaml: ][{"))
	require.Error(t, err)
}
