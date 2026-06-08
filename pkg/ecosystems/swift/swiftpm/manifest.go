package swiftpm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

const (
	packageManifestFile = "Package.swift"
	packageResolvedFile = "Package.resolved"
	defaultVersion      = "0.0.0"
)

// packageNameRe extracts the `name:` argument of `Package(...)` from a
// Package.swift manifest.
//
// Swift manifests are executable Swift code, not declarative data; a
// full-fidelity parse would require shelling out to swift itself. For our
// purposes — preferring the manifest's declared root name over swift's
// lower-cased identity — a regex on the well-known `Package(name: "...")`
// constructor is sufficient. The name argument is conventionally the first
// argument and is a string literal in every Swift package we've seen.
//
// We tolerate optional whitespace and the `name:` label being on its own line
// (which is the conventional formatting).
var packageNameRe = regexp.MustCompile(`(?m)Package\s*\(\s*name\s*:\s*"([^"]+)"`)

// packageManifest captures the fields we need from Package.swift.
type packageManifest struct {
	Name string
}

// readPackageManifest parses the Package.swift in dir and returns the
// declared package name. A missing file yields a typed error so the plugin
// can surface a friendly message; a parse failure yields the unparseable-
// manifest error type.
func readPackageManifest(dir string) (*packageManifest, error) {
	path := filepath.Join(dir, packageManifestFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, snykecosystems.NewUnprocessableFileError(
				fmt.Sprintf("%s not found: %v", packageManifestFile, err),
				snyk_errors.WithCause(err),
			)
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	name := parsePackageName(data)
	if name == "" {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Failed to parse %s: no Package(name:...) declaration found", packageManifestFile),
		)
	}

	return &packageManifest{Name: name}, nil
}

// parsePackageName returns the first `name:` argument of a `Package(...)`
// call in the manifest, or "" if no such constructor is found.
func parsePackageName(data []byte) string {
	m := packageNameRe.FindSubmatch(data)
	if m == nil {
		return ""
	}
	return string(m[1])
}
