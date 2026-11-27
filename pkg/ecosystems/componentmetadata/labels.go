// Package componentmetadata holds the dep-graph node labels that sbom-export
// turns into SBOM hashes and distribution references. Producers add them only
// when --include-component-metadata is set.
package componentmetadata

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
)

const (
	// HashLabelPrefix prefixes a hash label; the suffix is a canonical
	// algorithm name and the value a lowercase hex digest.
	HashLabelPrefix = "hash:"
	// DistributionURLLabel holds the URL of the artifact a node's hashes
	// describe, or of its index page when no file URL can be built.
	DistributionURLLabel = "distribution:url"
)

// hexLengths mirrors the hash algorithms sbom-export accepts, keyed by
// canonical label suffix, with the hex width a valid digest must have.
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
// hash in it must describe the same artifact as its distribution URL. The zero
// value is ready to use.
type Labels map[string]string

func (l *Labels) set(key, value string) {
	if *l == nil {
		*l = Labels{}
	}
	(*l)[key] = value
}

// AddHash adds a hex digest under its canonical key. It reports false, and
// adds nothing, when the algorithm is unsupported or the digest is not hex of
// the algorithm's width, the same checks sbom-export applies. Surrounding
// whitespace is trimmed.
func (l *Labels) AddHash(algorithm, hexDigest string) bool {
	alg, ok := CanonicalAlgorithm(algorithm)
	digest := strings.ToLower(strings.TrimSpace(hexDigest))
	if !ok || len(digest) != hexLengths[alg] {
		return false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return false
	}
	l.set(HashLabelPrefix+alg, digest)
	return true
}

// AddBase64Hash adds a base64 digest, padded or not, such as NuGet's
// .nupkg.sha512, after converting it to hex, since sbom-export drops non-hex
// values.
func (l *Labels) AddBase64Hash(algorithm, b64Digest string) bool {
	trimmed := strings.TrimSpace(b64Digest)
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(trimmed)
	}
	if err != nil {
		return false
	}
	return l.AddHash(algorithm, hex.EncodeToString(raw))
}

// AddDistributionURL adds a sanitized artifact URL. It reports false, and adds
// nothing, when SanitizeURL rejects it.
func (l *Labels) AddDistributionURL(rawURL string) bool {
	clean, ok := SanitizeURL(rawURL)
	if !ok {
		return false
	}
	l.set(DistributionURLLabel, clean)
	return true
}

// SanitizeURL strips credentials, query string and fragment from an absolute
// http or https URL, trims it and lowercases the host. ok is false for any
// other URL, and for a MyGet pre-authenticated feed URL (/F/<feed>/auth/<key>/).
//
// It does not find other tokens embedded in a path. Each resolver remains
// responsible for its own registries' URL shapes.
func SanitizeURL(rawURL string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", false
	}
	if hasAuthSegment(u.Path) {
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

// hasAuthSegment reports MyGet's pre-authenticated feed shape,
// /F/<feed>/auth/<key>/..., where the segment after "auth" is the API key.
// It matches only that shape: a package, crate or feed can itself be called
// "auth", and its URL must keep working.
func hasAuthSegment(path string) bool {
	segments := strings.Split(path, "/")
	for i := 2; i+1 < len(segments); i++ {
		if strings.EqualFold(segments[i], "auth") && strings.EqualFold(segments[i-2], "F") && segments[i+1] != "" {
			return true
		}
	}
	return false
}

// ApplyTo merges the labels into a dep-graph node, keeping any label the node
// already has. Hashes and the distribution URL are applied as one group: if
// the node already has any of them, none are added, so a node never mixes
// metadata from two artifacts. NodeInfo is created only when there is
// something to add.
func (l Labels) ApplyTo(node *depgraph.Node) {
	if len(l) == 0 {
		return
	}
	if node.Info == nil {
		node.Info = &depgraph.NodeInfo{}
	}
	if node.Info.Labels == nil {
		node.Info.Labels = make(map[string]string, len(l))
	}
	skipArtifact := hasArtifactLabel(node.Info.Labels)
	for k, v := range l {
		if skipArtifact && isArtifactLabel(k) {
			continue
		}
		if _, exists := node.Info.Labels[k]; !exists {
			node.Info.Labels[k] = v
		}
	}
}

func isArtifactLabel(key string) bool {
	return key == DistributionURLLabel || strings.HasPrefix(key, HashLabelPrefix)
}

func hasArtifactLabel(labels map[string]string) bool {
	for k := range labels {
		if isArtifactLabel(k) {
			return true
		}
	}
	return false
}
