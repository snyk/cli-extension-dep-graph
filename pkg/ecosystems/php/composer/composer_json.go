package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

const (
	composerJSONFile = "composer.json"
	composerLockFile = "composer.lock"
	defaultVersion   = "0.0.0"
)

// composerJSON captures the minimal subset of composer.json the plugin
// consumes to derive the root project's identity.
//
// Composer projects without a `name` field are valid (and common for
// applications rather than libraries) — in that case we fall back to the
// directory name. Composer's own `show --locked --tree` output does not
// echo the root package, so the root identity is entirely determined here.
type composerJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// readComposerJSON reads and parses composer.json in dir. A missing
// composer.json is non-fatal — callers fall back to the directory name for
// the root project's identity, matching the legacy snyk-php-plugin behavior
// (it tolerated missing root manifests in older fixtures).
//
// Parse failures are fatal: a present-but-invalid composer.json indicates a
// broken project and we surface the error verbatim rather than masquerade
// as a no-manifest case.
func readComposerJSON(dir string) (*composerJSON, error) {
	path := filepath.Join(dir, composerJSONFile)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &composerJSON{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var p composerJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Failed to parse %s: %v", composerJSONFile, err),
			snyk_errors.WithCause(err),
		)
	}

	return &p, nil
}

// rootProjectName returns the canonical root project name for a composer
// project living in dir.
//
// Preference order, mirroring legacy snyk-php-plugin:
//  1. composer.json `name` field if present
//  2. base name of dir (e.g. "/path/to/my-app" → "my-app")
func rootProjectName(pj *composerJSON, dir string) string {
	if pj != nil && pj.Name != "" {
		return pj.Name
	}
	return filepath.Base(dir)
}

// rootProjectVersion returns the canonical root project version.
//
// composer.json's `version` field is rarely populated for applications —
// composer recommends omitting it and inferring from git tags. We default
// to defaultVersion ("0.0.0") when absent, matching the npm plugin's
// convention and avoiding empty version strings in the produced graph.
func rootProjectVersion(pj *composerJSON) string {
	if pj != nil && pj.Version != "" {
		return pj.Version
	}
	return defaultVersion
}
