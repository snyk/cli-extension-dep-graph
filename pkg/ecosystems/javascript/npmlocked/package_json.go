package npmlocked

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

const (
	packageJSONFile = "package.json"
	packageLockFile = "package-lock.json"
	shrinkwrapFile  = "npm-shrinkwrap.json"
	defaultVersion  = "0.0.0"
)

// lockfileNames lists the lockfile filenames this plugin recognizes, in
// preferred order. npm itself prefers npm-shrinkwrap.json over
// package-lock.json when both are present in the same directory.
// `npm ls --package-lock-only` reads either format identically (verified
// empirically against npm 10.x).
var lockfileNames = []string{shrinkwrapFile, packageLockFile}

// isLockfileName reports whether base is one of our recognized lockfile
// filenames. base must be a basename, not a path.
func isLockfileName(base string) bool {
	for _, n := range lockfileNames {
		if base == n {
			return true
		}
	}
	return false
}

// packageJSON represents the fields we need from a package.json file.
type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// readPackageJSON reads and parses the package.json in the given directory.
func readPackageJSON(dir string) (*packageJSON, error) {
	path := filepath.Join(dir, packageJSONFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, snykecosystems.NewUnprocessableFileError(
				fmt.Sprintf("%s not found: %v", packageJSONFile, err),
				snyk_errors.WithCause(err),
			)
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var p packageJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Failed to parse %s: %v", packageJSONFile, err),
			snyk_errors.WithCause(err),
		)
	}

	if p.Version == "" {
		p.Version = defaultVersion
	}

	return &p, nil
}
