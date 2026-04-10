package bun

// pkgName is a bare npm package name.
// Examples: "debug", "@types/node", "@workspace/logger".
type pkgName string

// pkgVersion is a resolved package version string.
// Examples: "4.4.3", "workspace:packages/logger".
// Note: this is the installed version, not a semver constraint from package.json.
type pkgVersion string

// pkg identifies a specific resolved package by name and version.
type pkg struct {
	Name    pkgName
	Version pkgVersion
}

// nodeID returns the canonical "name@version" string used by the Snyk dep graph builder.
func (p pkg) nodeID() string {
	return string(p.Name) + "@" + string(p.Version)
}

// pkgSet is a set of resolved packages.
type pkgSet map[pkg]struct{}

// add inserts p into the set.
func (s pkgSet) add(p pkg) {
	s[p] = struct{}{}
}

// pkgRegistry maps bare package names to their resolved versions.
// It is built from the bun why output and used to resolve names to pkg values
// when seeding the dependency graph traversal.
type pkgRegistry map[pkgName]pkgVersion

// depEdges maps each resolved package to the set of packages it directly depends on.
// This is the forward adjacency representation of the dependency graph.
type depEdges map[pkg]pkgSet

// whyGraph holds the parsed and inverted output of `bun why '*' --top`.
type whyGraph struct {
	// Packages contains all resolved packages, indexed by bare name.
	Packages pkgRegistry
	// Dependencies maps each resolved package to its direct dependencies.
	Dependencies depEdges
}
