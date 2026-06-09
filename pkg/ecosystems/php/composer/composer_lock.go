package composer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// composerLockShape captures just enough of composer.lock to (a) verify it's
// well-formed JSON in cases where we need to flag the lockfile pre-CLI, and
// (b) provide a name→version map for identity disambiguation.
//
// We deliberately do NOT use this for dep-graph resolution: composer's
// `show --locked --tree` is the resolver of record. Reading the lockfile
// here is purely for identity reads (e.g. resolving aliases the CLI may
// have applied) and for surfacing a meaningful error when the lockfile is
// malformed before we even invoke composer.
type composerLockShape struct {
	Packages    []composerLockPackage `json:"packages"`
	PackagesDev []composerLockPackage `json:"packages-dev"`
}

// composerLockPackage is one entry in the lockfile's packages array. Only
// the fields used for identity reads are modeled.
type composerLockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// readComposerLock reads composer.lock from dir and returns its parsed
// shape, or an error wrapping the underlying os/json failure.
//
// A missing composer.lock is reported as os.ErrNotExist (via the wrapped
// error) so callers can decide whether to skip the project or report a
// hard failure.
func readComposerLock(dir string) (*composerLockShape, error) {
	path := filepath.Join(dir, composerLockFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var lock composerLockShape
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &lock, nil
}

// lockVersionMap returns a name→version map covering every package the
// lockfile declares, including dev packages.
//
// Used as a backstop when the tree parser encounters a specifier without
// an inline version (rare but possible at certain tree depths in
// composer 2.x for replace/provide/conflict entries).
func (l *composerLockShape) versionMap() map[string]string {
	if l == nil {
		return nil
	}
	out := make(map[string]string, len(l.Packages)+len(l.PackagesDev))
	for _, p := range l.Packages {
		if p.Name != "" {
			out[p.Name] = p.Version
		}
	}
	for _, p := range l.PackagesDev {
		if p.Name != "" {
			out[p.Name] = p.Version
		}
	}
	return out
}
