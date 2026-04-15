package bun

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	packageJSONFile = "package.json"
	bunLockFile     = "bun.lock"
	defaultVersion  = "0.0.0"
)

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
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var p packageJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if p.Name == "" {
		p.Name = filepath.Base(dir)
	}

	if p.Version == "" {
		p.Version = defaultVersion
	}

	return &p, nil
}
