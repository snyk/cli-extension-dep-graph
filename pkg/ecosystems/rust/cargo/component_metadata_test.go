package cargo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/componentmetadata"
)

// writeRegistryConfig mimics cargo's cache layout:
// $CARGO_HOME/registry/index/<host>-<16 hex>/config.json.
func writeRegistryConfig(t *testing.T, cargoHome, dirName, configJSON string) {
	t.Helper()
	dir := filepath.Join(cargoHome, "registry", "index", dirName)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(configJSON), 0o600))
}

// Expected values follow cargo's crate_url and make_dep_path
// (crates/cargo-util/src/registry.rs) and the dl field reference at
// doc.rust-lang.org/cargo/reference/registry-index.html.
func TestCrateURL(t *testing.T) {
	tests := []struct {
		name, dl, crate, version, want string
	}{
		{
			"plain dl appends crate/version/download", "https://dl.example.com/api/v1/crates", "serde", "1.0.0",
			"https://dl.example.com/api/v1/crates/serde/1.0.0/download",
		},
		{"crate and version markers", "https://dl.example.com/{crate}-{version}.crate", "serde", "1.0.0", "https://dl.example.com/serde-1.0.0.crate"},
		{"one-char prefix", "https://dl.example.com/{prefix}/{crate}", "a", "1.0.0", "https://dl.example.com/1/a"},
		{"two-char prefix", "https://dl.example.com/{prefix}/{crate}", "ab", "1.0.0", "https://dl.example.com/2/ab"},
		{"three-char prefix keeps case", "https://dl.example.com/{prefix}/{crate}", "Abc", "1.0.0", "https://dl.example.com/3/A/Abc"},
		{"four-plus prefix keeps case", "https://dl.example.com/{prefix}/{crate}", "aBcDe", "1.0.0", "https://dl.example.com/aB/cD/aBcDe"},
		{"lowerprefix", "https://dl.example.com/{lowerprefix}/{crate}", "aBcDe", "1.0.0", "https://dl.example.com/ab/cd/aBcDe"},
		{"checksum marker", "https://dl.example.com/{sha256-checksum}", "itoa", "1.0.11", "https://dl.example.com/" + itoaChecksum},
		{"empty name does not panic", "https://dl.example.com/{prefix}", "", "1.0.0", "https://dl.example.com/"},
		{
			"only checksum marker still suppresses suffix", "https://dl.example.com/by-hash/{sha256-checksum}", "itoa", "1.0.11",
			"https://dl.example.com/by-hash/" + itoaChecksum,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, crateURL(tt.dl, tt.crate, tt.version, itoaChecksum))
		})
	}
}

func TestRegistryConfigs_DL(t *testing.T) {
	t.Run("matches the cached index dir by host", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "my.registry.example-0123456789abcdef", `{"dl":"https://dl.example/{crate}/{version}"}`)
		writeRegistryConfig(t, home, "other.example-0123456789abcdef", `{"dl":"https://wrong.example"}`)

		dl, ok := newRegistryConfigs(home).dl("https://my.registry.example:8443/index/")
		require.True(t, ok)
		assert.Equal(t, "https://dl.example/{crate}/{version}", dl)
	})

	t.Run("IPv6 host dir keeps cargo's brackets", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "[::1]-0123456789abcdef", `{"dl":"http://[::1]:8080/dl"}`)

		dl, ok := newRegistryConfigs(home).dl("http://[::1]:8080/index/")
		require.True(t, ok)
		assert.Equal(t, "http://[::1]:8080/dl", dl)
	})

	// Upgrading cargo across rust-lang/cargo#14917 leaves two dirs for one
	// registry. When every dir has the same dl, the URL is the same whichever
	// one this source is.
	t.Run("several dirs with the same dl agree", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "reg.example-0123456789abcdef", `{"dl":"https://dl.example"}`)
		writeRegistryConfig(t, home, "reg.example-fedcba9876543210", `{"dl":"https://dl.example"}`)

		dl, ok := newRegistryConfigs(home).dl("https://reg.example/index")
		require.True(t, ok)
		assert.Equal(t, "https://dl.example", dl)
	})

	t.Run("several dirs with different dl values are ambiguous", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "reg.example-0123456789abcdef", `{"dl":"https://a.example"}`)
		writeRegistryConfig(t, home, "reg.example-fedcba9876543210", `{"dl":"https://b.example"}`)

		_, ok := newRegistryConfigs(home).dl("https://reg.example/index")
		assert.False(t, ok)
	})

	// Cargo keeps the host's case in the dir name: an index URL with
	// LOCALHOST is cached under LOCALHOST-<hash>.
	t.Run("matches the dir name case-insensitively", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "LOCALHOST-9d94d3d6719014a8", `{"dl":"http://localhost:18777/dl"}`)

		dl, ok := newRegistryConfigs(home).dl("sparse+http://LOCALHOST:18777/")
		require.True(t, ok)
		assert.Equal(t, "http://localhost:18777/dl", dl)
	})

	// Cargo's git index dirs hold .git and .cache but no config.json, so a
	// sparse dir on the same host must not win uncontested.
	t.Run("a dir without config.json still counts towards ambiguity", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "reg.example-0123456789abcdef", `{"dl":"https://sparse.example"}`)
		require.NoError(t, os.MkdirAll(filepath.Join(home, "registry", "index", "reg.example-fedcba9876543210", ".git"), 0o755))

		_, ok := newRegistryConfigs(home).dl("https://reg.example/index/")
		assert.False(t, ok)
	})

	t.Run("the host's only dir has no config.json", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(home, "registry", "index", "reg.example-0123456789abcdef", ".cache"), 0o755))

		_, ok := newRegistryConfigs(home).dl("https://reg.example/index/")
		assert.False(t, ok)
	})

	t.Run("host prefix of another host does not match", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "reg.example.org-0123456789abcdef", `{"dl":"https://a.example"}`)

		_, ok := newRegistryConfigs(home).dl("https://reg.example/index")
		assert.False(t, ok)
	})

	t.Run("uncached", func(t *testing.T) {
		_, ok := newRegistryConfigs(t.TempDir()).dl("https://reg.example/index")
		assert.False(t, ok)
	})

	t.Run("index dir without config.json or with bad json", func(t *testing.T) {
		home := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(home, "registry", "index", "reg.example-0123456789abcdef"), 0o755))
		writeRegistryConfig(t, home, "reg.example-fedcba9876543210", `{not json`)

		_, ok := newRegistryConfigs(home).dl("https://reg.example/index")
		assert.False(t, ok)
	})

	t.Run("empty dl", func(t *testing.T) {
		home := t.TempDir()
		writeRegistryConfig(t, home, "reg.example-0123456789abcdef", `{"api":"https://reg.example"}`)

		_, ok := newRegistryConfigs(home).dl("https://reg.example/index")
		assert.False(t, ok)
	})

	t.Run("unparseable index URL", func(t *testing.T) {
		_, ok := newRegistryConfigs(t.TempDir()).dl("::not a url")
		assert.False(t, ok)
	})

	t.Run("no cargo home", func(t *testing.T) {
		_, ok := newRegistryConfigs("").dl("https://reg.example/index")
		assert.False(t, ok)
	})
}

func TestBuildComponentLabels(t *testing.T) {
	home := t.TempDir()
	writeRegistryConfig(t, home, "templated.example-0123456789abcdef",
		`{"dl":"https://dl.templated.example/{lowerprefix}/{crate}/{crate}-{version}.crate?token=x"}`)
	writeRegistryConfig(t, home, "plain.example-0123456789abcdef", `{"dl":"https://u:p@dl.plain.example/api/v1/crates"}`)
	writeRegistryConfig(t, home, "query.example-0123456789abcdef", `{"dl":"https://dl.query.example/download?crate={crate}&v={version}"}`)

	pkgs := []lockPackage{
		{Name: "itoa", Version: "1.0.11", Source: cratesIOGit, Checksum: itoaChecksum},
		{Name: "serde", Version: "1.0.193", Source: cratesIOSparse, Checksum: serdeChecksum},
		{Name: "MyCrate", Version: "2.0.0", Source: "sparse+https://templated.example/index/", Checksum: serdeChecksum},
		{Name: "plaincrate", Version: "0.3.0", Source: "sparse+https://plain.example/index/", Checksum: itoaChecksum},
		// A git-index alt registry: cargo caches no config.json for it, so
		// only the hash is emitted even though plain.example has a sparse dir.
		{Name: "gitreg", Version: "0.4.0", Source: "registry+https://plain.example/git/index", Checksum: itoaChecksum},
		// Markers in the query string would be stripped by sanitizing,
		// collapsing every crate to one URL.
		{Name: "querycrate", Version: "0.5.0", Source: "sparse+https://query.example/index/", Checksum: itoaChecksum},
		{Name: "uncached", Version: "0.1.0", Source: "sparse+https://uncached.example/index/", Checksum: itoaChecksum},
		{Name: "gitdep", Version: "0.2.0", Source: "git+https://github.com/example/gitdep?branch=main#0123456789abcdef"},
		{Name: "pathdep", Version: "0.1.0"},
		{Name: "dup", Version: "1.0.0", Source: cratesIOGit, Checksum: itoaChecksum},
		{Name: "dup", Version: "1.0.0", Source: "sparse+https://plain.example/index/", Checksum: serdeChecksum},
		// A workspace member: no source, no checksum.
		{Name: "my-app", Version: "0.1.0"},
		{Name: "badsum", Version: "1.0.0", Source: cratesIOGit, Checksum: "not-hex"},
	}
	got := buildComponentLabels(pkgs, newRegistryConfigs(home))

	assert.Equal(t, map[string]componentmetadata.Labels{
		"itoa@1.0.11": {
			"hash:sha-256":     itoaChecksum,
			"distribution:url": "https://static.crates.io/crates/itoa/1.0.11/download",
		},
		"serde@1.0.193": {
			"hash:sha-256":     serdeChecksum,
			"distribution:url": "https://static.crates.io/crates/serde/1.0.193/download",
		},
		"MyCrate@2.0.0": {
			"hash:sha-256":     serdeChecksum,
			"distribution:url": "https://dl.templated.example/my/cr/MyCrate/MyCrate-2.0.0.crate",
		},
		"plaincrate@0.3.0": {
			"hash:sha-256":     itoaChecksum,
			"distribution:url": "https://dl.plain.example/api/v1/crates/plaincrate/0.3.0/download",
		},
		"uncached@0.1.0": {
			"hash:sha-256": itoaChecksum,
		},
		"gitreg@0.4.0": {
			"hash:sha-256": itoaChecksum,
		},
		"querycrate@0.5.0": {
			"hash:sha-256": itoaChecksum,
		},
		"badsum@1.0.0": {
			"distribution:url": "https://static.crates.io/crates/badsum/1.0.0/download",
		},
	}, got)
}

func TestBuildComponentLabels_ChecksumTemplateWithoutChecksum(t *testing.T) {
	home := t.TempDir()
	writeRegistryConfig(t, home, "reg.example-0123456789abcdef", `{"dl":"https://dl.example/{sha256-checksum}"}`)

	got := buildComponentLabels([]lockPackage{
		{Name: "nosum", Version: "1.0.0", Source: "sparse+https://reg.example/index/"},
	}, newRegistryConfigs(home))

	assert.Empty(t, got)
}
