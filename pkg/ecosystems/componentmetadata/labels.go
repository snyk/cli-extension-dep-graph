// Package componentmetadata holds the dep-graph node label vocabulary that
// sbom-export turns into CycloneDX hashes and distribution references, and
// SPDX checksums. It describes the packages in a graph; the metadata package,
// by contrast, holds keys describing the resolver that built it.
//
// Producers attach these labels to dep-graph nodes only when
// --include-component-metadata is set. Keeping the vocabulary in one place
// stops each Go resolver drifting from the contract sbom-export enforces:
// sbom-export silently drops a hash whose key or digest it does not
// recognize, so a mislabelled hash is lost rather than reported.
package componentmetadata

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

const (
	// HashLabelPrefix prefixes a hash label; the suffix is a canonical
	// algorithm name and the value a lowercase hex digest.
	HashLabelPrefix = "hash:"
	// DistributionURLLabel holds the URL of the artifact a node's hashes
	// describe, or of its index page when no file URL can be built.
	DistributionURLLabel = "distribution:url"
)

// hexLengths mirrors sbom-export's hashAlgorithms table
// (internal/sbom/hashes.go): the algorithms it accepts, keyed by canonical
// label suffix, with the hex width a valid digest must have.
var hexLengths = map[string]int{
	"md5":      32,
	"sha-1":    40,
	"sha-256":  64,
	"sha-384":  96,
	"sha-512":  128,
	"sha3-256": 64,
	"sha3-384": 96,
	"sha3-512": 128,
}

var algSeparators = strings.NewReplacer("-", "", "_", "")

// canonicalByCompact keys each supported algorithm by its name lowercased with
// separators removed. A lookup table, not prefix parsing: "sha384" and
// "sha3-84" would otherwise both compact to a "sha3" prefix.
var canonicalByCompact = func() map[string]string {
	m := make(map[string]string, len(hexLengths))
	for canonical := range hexLengths {
		m[algSeparators.Replace(canonical)] = canonical
	}
	return m
}()

// CanonicalAlgorithm maps the spellings package managers use ("sha256",
// "SHA-256", "sha3_256") to the label suffix sbom-export expects. ok is false
// for an algorithm sbom-export does not support.
func CanonicalAlgorithm(name string) (string, bool) {
	canonical, ok := canonicalByCompact[algSeparators.Replace(strings.ToLower(name))]
	return canonical, ok
}

// Labels collects component-metadata labels for one dep-graph node. Every
// hash in it must describe the same artifact as its distribution URL.
// Create it with Labels{}: like any map, a nil Labels panics on the first add.
type Labels map[string]string

// AddHash adds a hex digest under its canonical key. It reports false, and
// adds nothing, when the algorithm is unsupported or the digest is not hex of
// the algorithm's width, the same checks sbom-export applies.
func (l Labels) AddHash(algorithm, hexDigest string) bool {
	alg, ok := CanonicalAlgorithm(algorithm)
	if !ok || len(hexDigest) != hexLengths[alg] {
		return false
	}
	lower := strings.ToLower(hexDigest)
	if _, err := hex.DecodeString(lower); err != nil {
		return false
	}
	l[HashLabelPrefix+alg] = lower
	return true
}

// AddBase64Hash adds a base64 digest, such as NuGet's .nupkg.sha512, after
// converting it to hex, since sbom-export drops non-hex values.
func (l Labels) AddBase64Hash(algorithm, b64Digest string) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64Digest))
	if err != nil {
		return false
	}
	return l.AddHash(algorithm, hex.EncodeToString(raw))
}

// AddDistributionURL adds a sanitized artifact URL. It reports false, and adds
// nothing, when the URL is not an absolute http or https URL.
func (l Labels) AddDistributionURL(rawURL string) bool {
	clean, ok := SanitizeURL(rawURL)
	if !ok {
		return false
	}
	l[DistributionURLLabel] = clean
	return true
}

// SanitizeURL reduces a URL to its identity before it becomes a label:
// credentials, query string and fragment are removed, because any of them can
// carry authentication material and none identifies the artifact. Private
// hosts are kept; naming an internal registry is the point of the label. ok is
// false for anything other than an absolute http or https URL, which rules out
// path, file and VCS sources.
//
// Surrounding whitespace is trimmed and the host lowercased, as the WHATWG URL
// parser does in the TypeScript producers (snyk-poetry-lockfile-parser), so a
// package gets the same label whichever resolver produced it.
func SanitizeURL(rawURL string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	u.Host = strings.ToLower(u.Host)
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), true
}
