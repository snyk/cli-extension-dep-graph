package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// lockfilePackagesShape is the minimal subset of package-lock.json (v2/v3) we
// need to identify workspace packages. Each entry under "packages" whose key is
// a relative directory (not a "node_modules/..." path) describes either the
// root project or a workspace; we use the entry's embedded "name" field to map
// each workspace package back to its on-disk directory.
type lockfilePackagesShape struct {
	Packages map[string]struct {
		Name string `json:"name"`
		Link bool   `json:"link"`
	} `json:"packages"`
}

// readWorkspacePaths returns a map of workspace package name → relative
// directory (relative to the lockfile dir) parsed from package-lock.json.
//
// We need this because `npm ls --json` reports workspace paths as
// "file:../../packages/x" (relative to a phantom node_modules location), which
// would resolve incorrectly if used as a target-file path. The lockfile, in
// contrast, keys workspaces by their canonical relative directories.
//
// Returns an empty map (not an error) if the lockfile is missing, unparseable,
// or contains no workspaces — workspaces are not a hard requirement and a
// degraded result is better than failing the entire scan.
func readWorkspacePaths(lockfileDir string) map[string]string {
	data, err := os.ReadFile(filepath.Join(lockfileDir, packageLockFile))
	if err != nil {
		return nil
	}

	var shape lockfilePackagesShape
	if err := json.Unmarshal(data, &shape); err != nil {
		return nil
	}

	out := make(map[string]string)
	for relPath, pkg := range shape.Packages {
		// Root entry has an empty key; "node_modules/..." entries describe
		// resolved installs (workspaces of those appear as link: true with no
		// useful path); only bare relative dirs identify workspace sources.
		if relPath == "" || pkg.Link || pkg.Name == "" {
			continue
		}
		if filepath.IsAbs(relPath) {
			continue
		}
		// Skip node_modules entries.
		if hasNodeModulesPrefix(relPath) {
			continue
		}
		out[pkg.Name] = filepath.Clean(relPath)
	}
	return out
}

const nodeModulesPrefix = "node_modules/"

func hasNodeModulesPrefix(p string) bool {
	// Use filepath.ToSlash to normalise separators before checking.
	return len(p) >= len(nodeModulesPrefix) && filepath.ToSlash(p)[:len(nodeModulesPrefix)] == nodeModulesPrefix
}
