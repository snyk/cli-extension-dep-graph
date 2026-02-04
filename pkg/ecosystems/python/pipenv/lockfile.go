package pipenv

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// PipfileLock represents the structure of a Pipfile.lock file.
type PipfileLock struct {
	Meta    PipfileLockMeta          `json:"_meta"` //nolint:tagliatelle // Pipfile.lock uses _meta
	Default map[string]LockedPackage `json:"default"`
	Develop map[string]LockedPackage `json:"develop"`
}

// PipfileLockMeta contains metadata about the lock file.
type PipfileLockMeta struct {
	Hash     PipfileLockHash     `json:"hash"`
	Sources  []PipfileLockSource `json:"sources"`
	Requires PipfileLockRequires `json:"requires"`
}

// PipfileLockHash contains the hash of the Pipfile.
type PipfileLockHash struct {
	Sha256 string `json:"sha256"`
}

// PipfileLockSource represents a package source.
type PipfileLockSource struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	VerifySSL bool   `json:"verify_ssl"` //nolint:tagliatelle // Pipfile.lock uses snake_case
}

// PipfileLockRequires contains Python version requirements.
type PipfileLockRequires struct {
	PythonVersion string `json:"python_version"` //nolint:tagliatelle // Pipfile.lock uses snake_case
}

// LockedPackage represents a locked package in Pipfile.lock.
type LockedPackage struct {
	Version  string   `json:"version"`
	Hashes   []string `json:"hashes"`
	Markers  string   `json:"markers"`
	Index    string   `json:"index"`
	Extras   []string `json:"extras"`
	Git      string   `json:"git"`
	Ref      string   `json:"ref"`
	Path     string   `json:"path"`
	Editable bool     `json:"editable"`
}

// ParsePipfileLock reads and parses a Pipfile.lock from the given path.
func ParsePipfileLock(path string) (*PipfileLock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile.lock: %w", err)
	}

	var lockfile PipfileLock
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile.lock: %w", err)
	}

	return &lockfile, nil
}

// ToConstraints converts locked packages to pip constraints format.
// Each package is converted to a line like "package==version".
func (l *PipfileLock) ToConstraints(includeDevDeps bool) []string {
	var constraints []string

	// Process default (production) packages
	for name := range l.Default {
		pkg := l.Default[name]
		constraint := formatConstraint(name, &pkg)
		if constraint != "" {
			constraints = append(constraints, constraint)
		}
	}

	// Process develop packages if requested
	if includeDevDeps {
		for name := range l.Develop {
			pkg := l.Develop[name]
			constraint := formatConstraint(name, &pkg)
			if constraint != "" {
				constraints = append(constraints, constraint)
			}
		}
	}

	return constraints
}

// formatConstraint converts a locked package to constraints format.
func formatConstraint(name string, pkg *LockedPackage) string {
	// Skip git/path dependencies - they can't be constrained by version
	if pkg.Git != "" || pkg.Path != "" {
		return ""
	}

	// Version in Pipfile.lock is always pinned in "==X.Y.Z" format
	version := pkg.Version
	if version == "" {
		return ""
	}

	// Normalize package name (replace underscores with hyphens, lowercase)
	normalizedName := strings.ToLower(strings.ReplaceAll(name, "_", "-"))

	// Pipfile.lock versions are always pinned with ==
	if strings.HasPrefix(version, "==") {
		return normalizedName + version
	}

	return normalizedName + "==" + version
}
