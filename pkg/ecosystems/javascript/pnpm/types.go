package pnpm

const (
	packageJSONFile = "package.json"
	pnpmLockFile    = "pnpm-lock.yaml"
	rushJSONFile    = "rush.json"
	defaultVersion  = "0.0.0"
)

// listProject is one importer entry from `pnpm list --json` (an array, one
// element per workspace project). Dependencies are a forward tree: each dep
// carries its resolved version and its own nested dependencies.
type listProject struct {
	Name                 string             `json:"name"`
	Version              string             `json:"version"`
	Path                 string             `json:"path"`
	Dependencies         map[string]listDep `json:"dependencies"`
	DevDependencies      map[string]listDep `json:"devDependencies"`
	OptionalDependencies map[string]listDep `json:"optionalDependencies"`
}

// listDep is a node in pnpm's forward dependency tree. A workspace
// cross-dependency has a Version of the form "link:<relpath>".
type listDep struct {
	From         string             `json:"from"`
	Version      string             `json:"version"`
	Path         string             `json:"path"`
	Resolved     string             `json:"resolved"`
	Dependencies map[string]listDep `json:"dependencies"`
}
