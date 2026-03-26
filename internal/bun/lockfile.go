package bun

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// trailingCommaRe matches a comma followed by optional whitespace then } or ].
// bun.lock v1 is JSON5-like and allows trailing commas.
var trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

const (
	BunLockFileName     = "bun.lock"
	PackageJSONFileName = "package.json"
	defaultVersion      = "0.0.0"
)

// LockV1 represents the bun.lock v1 JSON format.
type LockV1 struct {
	LockfileVersion int                     `json:"lockfileVersion"`
	ConfigVersion   int                     `json:"configVersion"`
	Workspaces      map[string]Workspace    `json:"workspaces"`
	Overrides       map[string]string       `json:"overrides"`
	Packages        map[string]PackageEntry `json:"packages"`
}

// Workspace represents a workspace entry (root "" or a sub-package path).
type Workspace struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// PackageEntry is a raw JSON array entry from the packages map.
// 4-element: ["name@version", "registry-url", {metadata}, "sha512-integrity"]
// 3-element: ["name@ref", {metadata}, "hash"] (e.g. GitHub packages)
type PackageEntry []json.RawMessage

// PackageMetadata holds the optional third-element fields of a package entry.
type PackageMetadata struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// ResolvedPackage is the parsed, usable representation of a packages entry.
type ResolvedPackage struct {
	Name    string
	Version string
	Deps    map[string]string // alias → version-range (production + optional)
}

// ParseLockfile reads and parses a bun.lock v1 JSON file.
func ParseLockfile(filePath string) (*LockV1, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bun.lock: %w", err)
	}

	// bun.lock v1 is JSON5-like and allows trailing commas — strip them first.
	data = trailingCommaRe.ReplaceAll(data, []byte("$1"))

	var lock LockV1
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse bun.lock JSON: %w", err)
	}

	if lock.LockfileVersion != 1 {
		return nil, fmt.Errorf("unsupported bun.lock version %d: only version 1 is supported", lock.LockfileVersion)
	}

	return &lock, nil
}

// BuildPackageMap creates a map of alias → ResolvedPackage from the packages section.
func BuildPackageMap(packages map[string]PackageEntry) (map[string]*ResolvedPackage, error) {
	pkgMap := make(map[string]*ResolvedPackage, len(packages))

	for alias, entry := range packages {
		if len(entry) < 3 {
			continue
		}

		// First element is always "name@version" or "name@ref".
		var nameAtVersion string
		if err := json.Unmarshal(entry[0], &nameAtVersion); err != nil {
			return nil, fmt.Errorf("failed to parse package name for alias %q: %w", alias, err)
		}

		name, version := parseNameVersion(nameAtVersion)

		// Metadata element: index 2 for 4-element arrays, index 1 for 3-element arrays.
		metaIdx := 2
		if len(entry) == 3 {
			metaIdx = 1
		}

		var meta PackageMetadata
		if err := json.Unmarshal(entry[metaIdx], &meta); err != nil {
			// Non-fatal: some packages have empty or non-object metadata.
			meta = PackageMetadata{}
		}

		deps := make(map[string]string)
		for k, v := range meta.Dependencies {
			deps[k] = v
		}
		for k, v := range meta.OptionalDependencies {
			deps[k] = v
		}

		pkgMap[alias] = &ResolvedPackage{
			Name:    name,
			Version: version,
			Deps:    deps,
		}
	}

	return pkgMap, nil
}

// parseNameVersion splits "express@4.18.2" or "@lezer/cpp@1.1.3" into name and version.
// For non-semver refs (GitHub, etc.) the version is the portion after the last '@'.
func parseNameVersion(nameAtVersion string) (name, version string) {
	// Find last '@' that is not at position 0 (scoped packages start with '@').
	idx := strings.LastIndex(nameAtVersion, "@")
	if idx <= 0 {
		return nameAtVersion, defaultVersion
	}

	return nameAtVersion[:idx], nameAtVersion[idx+1:]
}

// PackageJSON holds the minimal fields we need from package.json.
type PackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ReadPackageJSON reads name/version from a package.json file.
// Returns defaults if the file is missing or unparseable.
func ReadPackageJSON(dir string) PackageJSON {
	data, err := os.ReadFile(dir + "/" + PackageJSONFileName)
	if err != nil {
		return PackageJSON{Name: "root", Version: defaultVersion}
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return PackageJSON{Name: "root", Version: defaultVersion}
	}

	if pkg.Name == "" {
		pkg.Name = "root"
	}

	if pkg.Version == "" {
		pkg.Version = defaultVersion
	}

	return pkg
}
