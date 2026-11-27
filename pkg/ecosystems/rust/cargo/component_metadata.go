package cargo

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/componentmetadata"
)

const (
	// crates.io appears in Cargo.lock under its git index or, since cargo
	// 1.70 made sparse the default, its sparse index.
	cratesIOGitSource    = "registry+https://github.com/rust-lang/crates.io-index"
	cratesIOSparseSource = "sparse+https://index.crates.io/"
	// cratesIODL is the dl value of crates.io's config.json. Hard-coded so
	// crates.io crates get a URL even before cargo has cached the index.
	cratesIODL = "https://static.crates.io/crates"

	sparseSourcePrefix = "sparse+"

	// Cargo.lock's checksum is the SHA-256 of the .crate file, which cargo
	// verifies on download, so it describes the same file as the dl URL.
	checksumAlgorithm = "sha-256"
)

// buildComponentLabels joins Cargo.lock entries to dep-graph node IDs
// (name@version). Cargo.lock is keyed by name, version and source, but node
// IDs carry no source, so a name@version locked from two sources is skipped
// rather than given a hash that may belong to the other copy. Workspace
// members are skipped too: they are the project's own code, not artifacts.
func buildComponentLabels(
	pkgs []lockPackage,
	configs *registryConfigs,
) map[string]componentmetadata.Labels {
	seen := make(map[string]int, len(pkgs))
	for _, p := range pkgs {
		seen[p.Name+"@"+p.Version]++
	}

	out := make(map[string]componentmetadata.Labels)
	for _, p := range pkgs {
		id := p.Name + "@" + p.Version
		if seen[id] != 1 {
			continue
		}

		labels := componentmetadata.Labels{}
		if p.Checksum != "" {
			labels.AddHash(checksumAlgorithm, p.Checksum)
		}
		if u, ok := distributionURL(p, configs); ok {
			labels.AddDistributionURL(u)
		}
		if len(labels) > 0 {
			out[id] = labels
		}
	}
	return out
}

// distributionURL builds the .crate download URL for a registry package. Git
// and path packages have no registry source and get none.
//
// Alternative registries get a URL only through a sparse index: cargo caches
// config.json for sparse indexes, but its git index checkouts hold only .git
// and .cache, so a git-index registry gets its hash and no URL rather than a
// dl borrowed from another registry on the same host.
//
// The URL is sanitized by componentmetadata.SanitizeURL, which drops
// credentials, query and fragment. Other path-embedded tokens (Cloudsmith
// style) are not stripped, as in poetry.
func distributionURL(p lockPackage, configs *registryConfigs) (string, bool) {
	var dl string
	switch {
	case p.Source == cratesIOGitSource || p.Source == cratesIOSparseSource:
		dl = cratesIODL
	case strings.HasPrefix(p.Source, sparseSourcePrefix):
		var ok bool
		if dl, ok = configs.dl(strings.TrimPrefix(p.Source, sparseSourcePrefix)); !ok {
			return "", false
		}
	default:
		return "", false
	}

	if p.Checksum == "" && strings.Contains(dl, checksumMarker) {
		return "", false
	}
	// Markers in the query or fragment would be stripped by sanitizing,
	// leaving one URL shared by every crate of the registry.
	if i := strings.IndexAny(dl, "?#"); i >= 0 && hasMarker(dl[i:]) {
		return "", false
	}
	return crateURL(dl, p.Name, p.Version, p.Checksum), true
}

const (
	crateMarker       = "{crate}"
	versionMarker     = "{version}"
	prefixMarker      = "{prefix}"
	lowerPrefixMarker = "{lowerprefix}"
	checksumMarker    = "{sha256-checksum}"
)

// crateURL applies cargo's dl template rule (crate_url in
// crates/cargo-util/src/registry.rs; registry-index.html in the cargo book):
// substitute the markers when any is present, otherwise append
// /{crate}/{version}/download.
func crateURL(dl, crate, version, checksum string) string {
	if !hasMarker(dl) {
		return dl + "/" + crate + "/" + version + "/download"
	}

	prefix := cratePrefix(crate)
	return strings.NewReplacer(
		crateMarker, crate,
		versionMarker, version,
		prefixMarker, prefix,
		lowerPrefixMarker, strings.ToLower(prefix),
		checksumMarker, checksum,
	).Replace(dl)
}

func hasMarker(s string) bool {
	for _, m := range []string{crateMarker, versionMarker, prefixMarker, lowerPrefixMarker, checksumMarker} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// cratePrefix mirrors cargo's make_dep_path(name, true): the index directory
// of a crate, from the name as written (not lowercased).
func cratePrefix(name string) string {
	switch len(name) {
	case 0:
		return ""
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3/" + name[:1]
	default:
		return name[0:2] + "/" + name[2:4]
	}
}

// registryConfigs finds the dl value of sparse alternative registries from
// the config.json cargo caches under $CARGO_HOME/registry/index/<dir>/. It
// never touches the network: an uncached registry yields no URL.
//
// Cargo names <dir> "<host>-<16 hex hash>" (short_name in
// src/cargo/sources/registry/mod.rs), with the host as the url crate prints
// it, so IPv6 hosts keep their brackets. The hash is of cargo's internal
// SourceId and has changed between cargo releases, so it is not recomputed.
// Instead every dir whose name matches the host, compared case-insensitively
// because cargo keeps the host's original case, must have a readable
// config.json with the same dl. Two dirs can be one registry cached by two
// cargo releases, or two registries on one host; when their dl values agree
// the URL is the same either way, and when they differ, or one cannot be read,
// which one is this source cannot be told.
type registryConfigs struct {
	cargoHome string
	cache     map[string]registryDL
}

type registryDL struct {
	dl string
	ok bool
}

func newRegistryConfigs(cargoHome string) *registryConfigs {
	return &registryConfigs{cargoHome: cargoHome, cache: make(map[string]registryDL)}
}

func (r *registryConfigs) dl(indexURL string) (string, bool) {
	if cached, ok := r.cache[indexURL]; ok {
		return cached.dl, cached.ok
	}
	dl, ok := r.lookup(indexURL)
	r.cache[indexURL] = registryDL{dl: dl, ok: ok}
	return dl, ok
}

func (r *registryConfigs) lookup(indexURL string) (string, bool) {
	if r.cargoHome == "" {
		return "", false
	}
	u, err := url.Parse(indexURL)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	dirName := regexp.MustCompile(`(?i)^` + regexp.QuoteMeta(host) + `-[0-9a-f]{16}$`)

	indexDir := filepath.Join(r.cargoHome, registryIndexPath)
	entries, err := os.ReadDir(indexDir)
	if err != nil {
		return "", false
	}

	found := ""
	for _, e := range entries {
		if !e.IsDir() || !dirName.MatchString(e.Name()) {
			continue
		}
		dl, ok := readRegistryDL(filepath.Join(indexDir, e.Name(), "config.json"))
		if !ok || (found != "" && dl != found) {
			return "", false
		}
		found = dl
	}
	return found, found != ""
}

func readRegistryDL(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var cfg struct {
		DL string `json:"dl"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", false
	}
	return cfg.DL, cfg.DL != ""
}

const (
	// cargoHomeEnv overrides cargo's home directory, as cargo itself reads it.
	cargoHomeEnv = "CARGO_HOME"
	// registryIndexPath is where cargo caches registry indexes under its home.
	registryIndexPath = "registry/index"
)

// cargoHomeDir follows cargo's default: $CARGO_HOME, else ~/.cargo.
func cargoHomeDir() string {
	if home := os.Getenv(cargoHomeEnv); home != "" {
		return home
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cargo")
}
