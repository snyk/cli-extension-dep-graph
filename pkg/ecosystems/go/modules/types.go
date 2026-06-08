package modules

// GoListPackage mirrors the JSON object emitted per-package by
// `go list -json -deps ./...`. The full schema is documented in
// `go help list`; we model only the fields we actually consume.
//
// `go list -deps ./...` emits a stream of these objects concatenated
// (NOT a JSON array). The executor wraps the stream into a valid array
// before decoding.
//
// Notes on selected fields:
//   - ImportPath: the fully-qualified import path; we use it as the
//     identity key when building the graph.
//   - DepOnly: false for packages directly listed by `./...` (the
//     project's own packages), true for transitive dependencies.
//   - Standard: true for packages in the Go standard library. We
//     filter these out unless the include-stdlib flag is on.
//   - Module: populated for non-stdlib packages; Module.Main marks
//     packages belonging to the root module.
//   - Imports: the package's direct imports — the edges of the graph.
type GoListPackage struct {
	Dir        string    `json:"Dir,omitempty"`
	ImportPath string    `json:"ImportPath"`
	Name       string    `json:"Name,omitempty"`
	Standard   bool      `json:"Standard,omitempty"`
	DepOnly    bool      `json:"DepOnly,omitempty"`
	Module     *GoModule `json:"Module,omitempty"`
	Imports    []string  `json:"Imports,omitempty"`
	Goroot     bool      `json:"Goroot,omitempty"`
}

// GoModule is the per-package `Module` block from `go list -json`.
//
// Replace is populated when a `replace` directive in go.mod redirects
// the module to a different module path / version. When useReplaceName
// is true the resolver substitutes the replaced module's path into the
// package name; the version is always taken from the replacement.
type GoModule struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version,omitempty"`
	Replace *GoModule `json:"Replace,omitempty"`
	Main    bool      `json:"Main,omitempty"`
}
