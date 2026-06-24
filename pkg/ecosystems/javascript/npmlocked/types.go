package npmlocked

// listResponse is the top-level JSON shape returned by `npm ls --json`.
//
// The lockfile-only invocation (`--package-lock-only`) still produces this same
// shape; the `Dependencies` map is nested recursively and `*Dep.Resolved` is
// populated from the lockfile for non-registry installs (workspaces, git, file).
//
// Problems is a structured list of issues npm encountered while walking the
// tree — typical entries look like "missing: pkg@1.0.0, required by app@1.0.0"
// or "invalid: pkg@2.0.0 (expected 1.x)". npm still emits a partial-but-usable
// dep tree alongside the problems; we surface them via the logger so customers
// see the actionable detail rather than a generic "npm ls failed" wrapping.
type listResponse struct {
	Name         string                      `json:"name"`
	Version      string                      `json:"version"`
	Problems     []string                    `json:"problems,omitempty"`
	Dependencies map[string]*listResponseDep `json:"dependencies,omitempty"`
}

// listResponseDep is one node in the `npm ls --json` tree.
//
// Resolved is used to identify workspace packages: workspaces always have a
// resolved URI beginning with "file:" (npm 7+) or are written as bare relative
// paths in older outputs. We treat any "file:"-prefixed resolved value as a
// workspace boundary.
//
// `Dependencies` may be nil (leaf) or populated for transitive children.
type listResponseDep struct {
	Version      string                      `json:"version"`
	Resolved     string                      `json:"resolved,omitempty"`
	Dependencies map[string]*listResponseDep `json:"dependencies,omitempty"`
}
