package yarn

// forwardGraph maps each package ID to the set of package IDs it directly
// depends on. Both Yarn Classic (`yarn list --json`) and Berry (`yarn info -AR
// --json`) emit forward adjacency; parsers normalise into this single shape.
//
// IDs are kept in the form emitted by yarn:
//   - Classic: "name@resolvedVersion"          e.g. "accepts@1.3.7"
//   - Berry:   "name@protocol:identifier"      e.g. "debug@npm:4.3.1"
//     "logger@workspace:packages/logger"
//
// splitPkgID in depgraph.go strips protocol prefixes when populating PkgInfo,
// but graph keys remain raw to preserve uniqueness across protocols.
type forwardGraph map[string]map[string]struct{}

// workspaceInfo describes a workspace package found in the project.
type workspaceInfo struct {
	// Dir is the workspace's path relative to the lockfile directory.
	// "" or "." means the workspace is the root project itself.
	Dir string

	// Name and Version come from the workspace's package.json. Version defaults
	// to "0.0.0" if the workspace's package.json has no version field.
	Name    string
	Version string
}

// parsedOutput is the unified intermediate representation produced by both
// yarn parsers (list for v1, info for Berry). depgraph.go consumes it without
// knowing which parser produced it.
type parsedOutput struct {
	// Graph holds forward dependency edges between resolved packages.
	// Workspace packages appear as keys too (their entry holds their deps).
	Graph forwardGraph

	// ProdDeps is the set of package IDs directly depended on by the root
	// project as production / optional / peer dependencies.
	ProdDeps []string

	// DevDeps is the set of package IDs directly depended on by the root
	// project as dev dependencies. Yarn's CLI does not always distinguish dev
	// from prod (e.g. `yarn info` doesn't); when unknown, parsers leave this
	// empty and put everything in ProdDeps.
	DevDeps []string

	// Workspaces enumerates workspace packages keyed by their full ID. Each
	// gets its own dep graph emitted by depgraph.go. Includes the root only
	// when the root itself is a named workspace package (Berry always; Classic
	// only when the root has a "workspaces" field).
	Workspaces map[string]workspaceInfo
}
