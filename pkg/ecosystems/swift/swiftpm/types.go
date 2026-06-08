package swiftpm

// depTreeNode is one node in `swift package show-dependencies --format json`.
//
// The top-level node describes the root project; nested `Dependencies` form
// the transitive tree. Cycles are possible because Swift packages can depend
// on each other through path: / branch: links; the dep-graph build pass
// guards against this with a visited set.
//
// Field meanings (from `swift-package-manager` sources, file
// Sources/Commands/PackageCommands/ShowDependencies.swift):
//
//   - Identity:    Lower-cased canonical identity computed from the package's
//                  resolved URL (e.g. "swift-argument-parser").
//   - Name:        The `name` from the manifest's Package(name:) initializer.
//   - URL:         The original URL (git remote, local path, or registry
//                  identity like "apple.swift-argument-parser").
//   - Version:     Resolved semver, or "unspecified" for the root and for
//                  path: / branch: deps.
//   - Path:        On-disk path to the resolved checkout. We only use this
//                  for diagnostics; identity comes from URL + Version.
//   - Dependencies: Direct dependencies — recursively populated.
type depTreeNode struct {
	Identity     string         `json:"identity,omitempty"`
	Name         string         `json:"name"`
	URL          string         `json:"url"`
	Version      string         `json:"version"`
	Path         string         `json:"path,omitempty"`
	Dependencies []*depTreeNode `json:"dependencies"`
}
