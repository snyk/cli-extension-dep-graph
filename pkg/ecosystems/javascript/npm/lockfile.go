package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// lockfilePackagesShape is the minimal subset of package-lock.json (v2/v3) we
// need to identify workspace packages.
//
// Workspaces appear in the lockfile two ways:
//
//  1. A link entry under "node_modules/<name>" with `"link": true` and
//     `"resolved": "<relpath>"` — present in every npm-generated v2/v3
//     lockfile that has workspaces. The name is derived from the key.
//  2. A source entry keyed by the workspace's relative directory (e.g.
//     "packages/a"). The embedded "name" field is only sometimes populated
//     — npm often omits it on workspaces whose name equals the dir basename.
//
// We rely on (1) because it is the only consistently-named representation.
type lockfilePackagesShape struct {
	Packages map[string]struct {
		Name     string `json:"name"`
		Link     bool   `json:"link"`
		Resolved string `json:"resolved"`
	} `json:"packages"`
}

// readWorkspacePaths returns a map of workspace package name → relative
// directory (relative to the lockfile dir) parsed from package-lock.json.
//
// We need this because `npm ls --json` reports workspace paths as
// "file:../../packages/x" (relative to a phantom node_modules location), which
// would resolve incorrectly if used as a target-file path. The lockfile, in
// contrast, keys workspace install links by their canonical relative dirs.
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
	for key, pkg := range shape.Packages {
		// Workspace link entries — "node_modules/<name>" with link:true and a
		// resolved relpath. The name (including scope like "@scope/x") is
		// everything after the "node_modules/" prefix.
		if pkg.Link && pkg.Resolved != "" && hasNodeModulesPrefix(key) {
			name := strings.TrimPrefix(filepath.ToSlash(key), nodeModulesPrefix)
			if name == "" || filepath.IsAbs(pkg.Resolved) {
				continue
			}
			out[name] = filepath.Clean(pkg.Resolved)
		}
	}
	return out
}

const nodeModulesPrefix = "node_modules/"

func hasNodeModulesPrefix(p string) bool {
	// Use filepath.ToSlash to normalise separators before checking.
	return len(p) >= len(nodeModulesPrefix) && filepath.ToSlash(p)[:len(nodeModulesPrefix)] == nodeModulesPrefix
}
