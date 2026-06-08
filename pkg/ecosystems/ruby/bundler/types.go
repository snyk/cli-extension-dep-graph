package bundler

// SpecSource identifies which top-level lockfile block a spec was
// declared under. Bundler's Gemfile.lock has one block per source:
// GEM (rubygems-style remote), GIT (git repo), PATH (local path).
type SpecSource string

const (
	SourceGEM  SpecSource = "GEM"
	SourceGIT  SpecSource = "GIT"
	SourcePATH SpecSource = "PATH"
)

// SourceMeta captures the per-block metadata that appears before the
// `specs:` list (remote URL, git revision, optional branch/ref).
// Multiple GIT/GEM/PATH blocks can exist; each gem under specs: is
// tagged with the SourceMeta of its enclosing block via its Spec entry.
type SourceMeta struct {
	Type     SpecSource
	Remote   string // URL for GEM/GIT; path for PATH.
	Revision string // GIT only: full commit SHA.
	Ref      string // GIT only: pinned ref/SHA from the Gemfile.
	Branch   string // GIT only: branch.
	Tag      string // GIT only: tag.
	Glob     string // PATH only.
}

// Spec is one resolved gem in a Gemfile.lock specs: list.
// Children are direct dependency names (no version constraints retained;
// resolution happens by looking up the name in Lockfile.Specs).
type Spec struct {
	Name     string
	Version  string
	Source   *SourceMeta // nil if for some reason source block was missing.
	Children []string    // gem names of direct dependencies, in lockfile order.
}

// Dependency is one entry in the top-level DEPENDENCIES block, which
// lists root dependencies declared in the Gemfile. The `!` marker (used
// by git/path-sourced gems) is stripped from Name; Pinned records
// whether the marker was present.
type Dependency struct {
	Name   string
	Pinned bool   // The original line ended in `!`.
	Group  string // Always "" today — Gemfile.lock doesn't encode groups.
}

// Lockfile is the fully-parsed representation of a Gemfile.lock.
type Lockfile struct {
	// Specs maps gem name → resolved Spec across every source block.
	// If two GEM blocks list the same gem, the last one wins (matches legacy
	// @snyk/gemfile behavior which folds all source blocks into one map).
	Specs map[string]*Spec

	// Dependencies preserves the lockfile order of the top-level
	// DEPENDENCIES block so dep-graph roots are deterministic.
	Dependencies []Dependency

	// Platforms is metadata only — preserved for future use, not
	// enforced when walking the graph (legacy parity).
	Platforms []string

	// BundledWith is the bundler version recorded in BUNDLED WITH.
	BundledWith string

	// RubyVersion is the ruby runtime line, if present (e.g. "2.3.1p0").
	RubyVersion string
}
