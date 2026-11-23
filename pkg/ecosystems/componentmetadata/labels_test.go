package componentmetadata_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/componentmetadata"
)

func TestCanonicalAlgorithm(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"md5", "md5", true},
		{"sha1", "sha-1", true},
		{"SHA-1", "sha-1", true},
		{"sha256", "sha-256", true},
		{"SHA256", "sha-256", true},
		{"sha_256", "sha-256", true},
		{"sha384", "sha-384", true},
		{"sha512", "sha-512", true},
		{"sha3-256", "sha3-256", true},
		{"sha3_384", "sha3-384", true},
		{"SHA3-512", "sha3-512", true},
		{"blake2b", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := componentmetadata.CanonicalAlgorithm(tt.in)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLabels_AddHash(t *testing.T) {
	sha256 := "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

	t.Run("adds a lowercased hex digest under its canonical key", func(t *testing.T) {
		l := componentmetadata.Labels{}
		assert.True(t, l.AddHash("sha256", sha256))
		assert.Equal(t, componentmetadata.Labels{
			"hash:sha-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		}, l)
	})

	t.Run("rejects a digest of the wrong width", func(t *testing.T) {
		l := componentmetadata.Labels{}
		assert.False(t, l.AddHash("sha-512", sha256))
		assert.Empty(t, l)
	})

	t.Run("rejects base64, which fails on width", func(t *testing.T) {
		l := componentmetadata.Labels{}
		assert.False(t, l.AddHash("sha-256", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="))
		assert.Empty(t, l)
	})

	// Right width, wrong alphabet: only the hex check can reject these.
	t.Run("rejects non-hex digests of the right width", func(t *testing.T) {
		for alg, width := range map[string]int{"sha-256": 64, "sha3-512": 128, "md5": 32} {
			l := componentmetadata.Labels{}
			assert.False(t, l.AddHash(alg, strings.Repeat("z", width)), alg)
			assert.Empty(t, l, alg)
		}
	})

	t.Run("a rejected hash leaves existing labels untouched", func(t *testing.T) {
		l := componentmetadata.Labels{"hash:sha-256": "kept"}
		assert.False(t, l.AddHash("sha-256", strings.Repeat("z", 64)))
		assert.Equal(t, componentmetadata.Labels{"hash:sha-256": "kept"}, l)
	})

	t.Run("rejects an unsupported algorithm", func(t *testing.T) {
		l := componentmetadata.Labels{}
		assert.False(t, l.AddHash("blake2b", sha256))
		assert.Empty(t, l)
	})
}

func TestLabels_AddBase64Hash(t *testing.T) {
	// SHA-512 of the empty string.
	b64 := "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
	hex := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

	l := componentmetadata.Labels{}
	assert.True(t, l.AddBase64Hash("sha512", b64))
	assert.Equal(t, componentmetadata.Labels{"hash:sha-512": hex}, l)

	assert.False(t, componentmetadata.Labels{}.AddBase64Hash("sha512", "not base64!"))
	assert.False(t, componentmetadata.Labels{}.AddBase64Hash("sha256", b64), "wrong width for the algorithm")
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"keeps a plain https URL", "https://static.crates.io/crates/itoa/1.0.11/download", "https://static.crates.io/crates/itoa/1.0.11/download", true},
		{"strips credentials", "https://u:p@feed.example/v3/index.json", "https://feed.example/v3/index.json", true},
		{"strips the query string", "https://files.example/pkg.whl?token=abc", "https://files.example/pkg.whl", true},
		{"strips the fragment", "https://files.example/pkg.whl#sha256=abc", "https://files.example/pkg.whl", true},
		{"keeps http for internal registries", "http://nexus.local/repo/pkg.tar.gz", "http://nexus.local/repo/pkg.tar.gz", true},
		{"rejects file URLs", "file:///home/me/pkg.whl", "", false},
		{"rejects git URLs", "git+https://github.com/org/repo", "", false},
		{"rejects relative paths", "../pkg.whl", "", false},
		{"rejects garbage", "://", "", false},
		{"rejects an empty string", "", "", false},
		{"trims surrounding whitespace", " https://h/x\n", "https://h/x", true},
		{"lowercases the host", "HTTPS://Example.COM/Simple/", "https://example.com/Simple/", true},
		{"drops a bare trailing ?", "https://h/x?", "https://h/x", true},
		{"strips percent-encoded credentials", "https://us%40er:pa%3Ass@h/x", "https://h/x", true},
		{"keeps an IPv6 host", "https://[::1]:8443/x", "https://[::1]:8443/x", true},
		{"rejects an opaque URL", "https:host/x", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := componentmetadata.SanitizeURL(tt.in)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLabels_AddDistributionURL(t *testing.T) {
	l := componentmetadata.Labels{}
	assert.True(t, l.AddDistributionURL("https://u:p@host/x?y=z"))
	assert.Equal(t, componentmetadata.Labels{"distribution:url": "https://host/x"}, l)

	l = componentmetadata.Labels{}
	assert.False(t, l.AddDistributionURL("file:///tmp/x"))
	assert.Empty(t, l)
}
