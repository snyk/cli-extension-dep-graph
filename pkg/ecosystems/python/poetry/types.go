// Package poetry implements the Snyk SCA plugin for Python projects
// managed with Poetry. It resolves the dependency graph by delegating
// to `POETRY_VIRTUALENVS_CREATE=false poetry show --tree --no-ansi`,
// which reads the project's poetry.lock without triggering an install
// or creating a virtualenv.
package poetry

const (
	// PluginName is the registered name of the poetry SCA plugin.
	PluginName = "poetry"

	// PkgManagerName is the dep-graph PkgManager.Name written into every
	// graph produced by this plugin. It matches the legacy value emitted
	// by snyk-poetry-lockfile-parser.
	PkgManagerName = "poetry"

	// LockFileName is the poetry lockfile we look for during discovery.
	LockFileName = "poetry.lock"

	// PyprojectTomlFileName is the poetry manifest sitting alongside
	// poetry.lock; we read it for the root package name and version.
	PyprojectTomlFileName = "pyproject.toml"

	// DefaultRootName matches the legacy snyk-poetry-lockfile-parser
	// fallback when the pyproject.toml has no name (e.g. package-mode=false).
	DefaultRootName = "_root"

	// DefaultRootVersion matches the legacy snyk-poetry-lockfile-parser
	// fallback when the pyproject.toml has no version.
	DefaultRootVersion = "0.0.0"
)

// treeNode is the parsed form of one line of `poetry show --tree` output.
// The tree is reconstructed by tracking each line's depth (computed from
// the leading indent width) and re-parenting accordingly.
type treeNode struct {
	// Name is the package name as printed by poetry (no normalisation
	// applied at parse time so that we can preserve identity).
	Name string

	// Version is the resolved concrete version for top-level entries,
	// or the constraint string for transitive entries — poetry's tree
	// output uses the constraint at the dependency edge. We resolve
	// constraints back to concrete versions during graph assembly via
	// a top-level name → version index.
	Version string

	// Depth is the indentation depth of this node (0 for top-level
	// installed packages, 1+ for transitive dependencies).
	Depth int

	// Children is populated during the second pass when the flat list
	// is reassembled into a tree.
	Children []*treeNode
}
