package npmlocked

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// lockfilePackagesShape is the minimal subset of package-lock.json (v2/v3) we
// need to identify workspace packages.
//
// Workspaces appear in the lockfile as a link entry under
// "node_modules/<name>" with `"link": true` and `"resolved": "<relpath>"`.
// The name is derived from the key.
//
// The same shape is also used for plain `file:` dependencies (local packages
// referenced without being declared as a workspace), so the link entry alone
// is ambiguous — we cross-reference against package.json's `workspaces` field
// to distinguish the two.
type lockfilePackagesShape struct {
	Packages map[string]struct {
		Name     string `json:"name"`
		Link     bool   `json:"link"`
		Resolved string `json:"resolved"`
	} `json:"packages"`
}

// rootPackageJSONShape captures just the workspaces field, which can be either
// `["packages/*", ...]` (npm/yarn classic) or `{"packages": ["packages/*"]}`
// (yarn classic alternative form). We accept both via json.RawMessage and try
// each shape in turn.
type rootPackageJSONShape struct {
	Workspaces json.RawMessage `json:"workspaces"`
}

// readWorkspacePaths returns a map of workspace package name → relative
// directory (relative to the lockfile dir) parsed from package-lock.json,
// filtered against the root package.json's `workspaces` declaration.
//
// We need this because `npm ls --json` reports workspace paths as
// "file:../../packages/x" (relative to a phantom node_modules location), which
// would resolve incorrectly if used as a target-file path. The lockfile, in
// contrast, keys workspace install links by their canonical relative dirs.
//
// The package.json cross-check matters because npm emits the same link-entry
// shape for both true workspaces and plain `file:` dependencies — without
// filtering, every `"foo": "file:./local"` dep would be misclassified as a
// workspace and get its own dep graph.
//
// Always returns a non-nil map. Empty when the lockfile is missing,
// unparseable, or the project declares no workspaces — workspaces are not a
// hard requirement and a degraded result is better than failing the entire
// scan.
func readWorkspacePaths(lockfileDir string) map[string]string {
	out := make(map[string]string)

	patterns := readWorkspacePatterns(lockfileDir)
	if len(patterns) == 0 {
		// No workspaces declared in package.json → no workspaces, regardless
		// of what link entries appear in the lockfile.
		return out
	}

	data, err := os.ReadFile(filepath.Join(lockfileDir, packageLockFile))
	if err != nil {
		return out
	}

	var shape lockfilePackagesShape
	if err := json.Unmarshal(data, &shape); err != nil {
		return out
	}
	for key, pkg := range shape.Packages {
		// Workspace link entries — "node_modules/<name>" with link:true and a
		// resolved relpath. The name (including scope like "@scope/x") is
		// everything after the "node_modules/" prefix.
		if !pkg.Link || pkg.Resolved == "" || !hasNodeModulesPrefix(key) {
			continue
		}
		name := strings.TrimPrefix(filepath.ToSlash(key), nodeModulesPrefix)
		if name == "" || filepath.IsAbs(pkg.Resolved) {
			continue
		}
		resolved := filepath.Clean(pkg.Resolved)
		if !matchesAnyWorkspacePattern(resolved, patterns) {
			// Link entry exists but the resolved path isn't covered by any
			// workspaces glob → it's a plain `file:` dep, not a workspace.
			continue
		}
		out[name] = resolved
	}
	return out
}

// readWorkspacePatterns returns the raw workspace glob/path patterns from the
// root package.json's `workspaces` field, supporting both the array form
// (`["packages/*"]`) and the object form (`{"packages": ["packages/*"]}`).
//
// Returns nil if package.json is missing, unparseable, or has no workspaces
// declaration — semantically equivalent to "this project has no workspaces".
func readWorkspacePatterns(dir string) []string {
	data, err := os.ReadFile(filepath.Join(dir, packageJSONFile))
	if err != nil {
		return nil
	}
	var shape rootPackageJSONShape
	if err := json.Unmarshal(data, &shape); err != nil {
		return nil
	}
	if len(shape.Workspaces) == 0 {
		return nil
	}

	// Array form.
	var arr []string
	if err := json.Unmarshal(shape.Workspaces, &arr); err == nil {
		return arr
	}

	// Object form: {"packages": [...]}.
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(shape.Workspaces, &obj); err == nil {
		return obj.Packages
	}

	return nil
}

// matchesAnyWorkspacePattern reports whether resolved (a lockfile-relative
// path) is covered by any of the workspace patterns. Patterns may be exact
// paths or single-level globs (e.g. `packages/*`). `filepath.Match` is used,
// which treats `/` as a separator — patterns like `packages/*` match
// `packages/a` but not `packages/a/b`. Multi-level globs (`**`) are not
// supported (npm itself uses a single-level interpretation here).
func matchesAnyWorkspacePattern(resolved string, patterns []string) bool {
	r := filepath.ToSlash(resolved)
	for _, pat := range patterns {
		p := filepath.ToSlash(pat)
		if p == r {
			return true
		}
		// filepath.Match only errors on a malformed pattern; we treat any such
		// pattern as non-matching and move on.
		ok, err := filepath.Match(p, r)
		if err == nil && ok {
			return true
		}
	}
	return false
}

const nodeModulesPrefix = "node_modules/"

func hasNodeModulesPrefix(p string) bool {
	// Use filepath.ToSlash to normalise separators before checking.
	return len(p) >= len(nodeModulesPrefix) && filepath.ToSlash(p)[:len(nodeModulesPrefix)] == nodeModulesPrefix
}
