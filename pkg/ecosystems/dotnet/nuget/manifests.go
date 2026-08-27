package nuget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// errNotDotnetManifest marks a file whose name this resolver matched but whose
// contents belong to another ecosystem. Reporting nothing for it is the right
// outcome and not a failure, so it is told apart from a manifest that is
// genuinely broken — see deferToLegacy.
var errNotDotnetManifest = errors.New("not a .NET manifest")

// declaredPackage is one dependency as a manifest names it, before the packages
// folder gets a say over the version.
type declaredPackage struct {
	name    string
	version string
}

// frameworkManifest is what a packages.config or project.json contributes to
// resolution. Both feed the same downstream path, so they are read into one
// shape here and differ only in what they can fill in.
type frameworkManifest struct {
	// packages is every dependency the manifest declares, in document order.
	// packages.config lists the whole flattened set, transitive dependencies
	// included; project.json lists only what the project asked for.
	packages []declaredPackage

	// frameworkHints are the targetFramework attributes a packages.config
	// carries, and are consulted only when the project has no .csproj. Always
	// empty for project.json: snyk-nuget-plugin gives it no such fallback, so a
	// project.json without a .csproj alongside it cannot be resolved.
	frameworkHints []string

	// rootName and rootVersion override the directory-derived defaults when a
	// project.json declares them. Empty otherwise, which is the usual case —
	// these fields belong to project.assets.json and are vanishingly rare here.
	rootName    string
	rootVersion string
}

// readPackagesConfig loads a packages.config.
//
// path is read; displayPath is what messages name, since discovery hands out
// absolute paths and quoting one leaks the build agent's layout.
func readPackagesConfig(path, displayPath string) (*frameworkManifest, error) {
	data, err := readManifestFile(path, displayPath)
	if err != nil {
		return nil, err
	}

	var doc struct {
		Packages []struct {
			ID              string `xml:"id,attr"`
			Version         string `xml:"version,attr"`
			TargetFramework string `xml:"targetFramework,attr"`
		} `xml:"package"`
	}

	if err := decodeXML(data, &doc); err != nil {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Could not parse %s as XML.", displayPath),
			snyk_errors.WithCause(err),
		)
	}

	// Decoding into a struct with no XMLName accepts any root element, so the
	// root is checked separately: snyk-nuget-plugin rejects a file whose root is
	// not <packages>, and a <package> element is matched by name wherever it
	// sits — so a NuGet.config-shaped file would otherwise parse cleanly and
	// look like an ordinary project.
	if root := xmlRootElement(data); root != "packages" {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("%s has a <%s> root element rather than <packages>. "+
				"See https://learn.microsoft.com/en-us/nuget/reference/packages-config#schema.", displayPath, root),
		)
	}

	manifest := &frameworkManifest{}

	for _, pkg := range doc.Packages {
		manifest.packages = append(manifest.packages, declaredPackage{name: pkg.ID, version: pkg.Version})

		if pkg.TargetFramework != "" {
			manifest.frameworkHints = append(manifest.frameworkHints, pkg.TargetFramework)
		}
	}

	return manifest, nil
}

// readProjectJSON loads a project.json.
//
// project.json predates the PackageReference format and lists only direct
// dependencies; the resolved set lived in project.lock.json, which neither this
// resolver nor snyk-nuget-plugin reads.
func readProjectJSON(path, displayPath string) (*frameworkManifest, error) {
	data, err := readManifestFile(path, displayPath)
	if err != nil {
		return nil, err
	}

	var doc orderedMap[json.RawMessage]
	if err := json.Unmarshal(toUTF8(data), &doc); err != nil {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Could not parse %s as JSON.", displayPath),
			snyk_errors.WithCause(err),
		)
	}

	// The same check snyk-nuget-plugin makes before committing to this parser.
	// project.json is a generic enough name that other ecosystems use it — Nx
	// workspaces most notably — and resolving one of those as a .NET project
	// would report nonsense rather than nothing.
	//
	// The error is a plain one rather than a catalog one: it is never shown to
	// anyone, because a file belonging to another ecosystem is not a problem to
	// report.
	if !hasAny(&doc, "dependencies", "frameworks", "runtimes", "supports") {
		return nil, fmt.Errorf("%w: %s declares none of dependencies, frameworks, runtimes or supports",
			errNotDotnetManifest, displayPath)
	}

	declared := newPackageSet()
	scanForDependencies(&doc, declared, maxProjectJSONDepth)

	manifest := &frameworkManifest{packages: declared.packages}
	manifest.rootName, manifest.rootVersion = projectJSONRoot(&doc)

	return manifest, nil
}

// readManifestFile reads a manifest, reporting a missing or unreadable one
// through the error catalog: the dep-graph workflow only shows the user a
// message when snyk_errors.Error.Detail is set.
func readManifestFile(path, displayPath string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, snykecosystems.NewUnprocessableFileError(
			fmt.Sprintf("Could not read %s: %v.", displayPath, readFailureReason(err)),
			snyk_errors.WithCause(err),
		)
	}

	return data, nil
}

// scanForDependencies walks the document and collects every object under a
// `dependencies` key, at any depth, mirroring snyk-nuget-plugin's function of
// the same name. That is how a project.json declaring per-framework
// dependencies under `frameworks.<tfm>.dependencies` is picked up without this
// resolver knowing the schema.
//
// A `dependencies` object is read one level deep and not descended into, so a
// package literally named "dependencies" is not mistaken for another group.
func scanForDependencies(node *orderedMap[json.RawMessage], into *packageSet, depth int) {
	if depth <= 0 {
		return
	}

	for _, key := range node.Keys() {
		raw, _ := node.Get(key)

		if key == "dependencies" {
			var group orderedMap[json.RawMessage]
			if err := json.Unmarshal(raw, &group); err != nil {
				continue
			}

			for _, name := range group.Keys() {
				value, _ := group.Get(name)
				into.set(name, dependencyVersion(value))
			}

			continue
		}

		descend(raw, into, depth-1)
	}
}

// descend walks into objects and arrays, which is where nested dependency
// groups live. Scalars terminate the walk.
//
// depth bounds how far down it goes. Each level re-decodes the subtree beneath
// it, so the walk costs time quadratic in nesting depth — a 48KB file nested
// 8000 deep takes four seconds. Real manifests nest a handful of levels, and
// anything approaching the bound is not a .NET project.json, so stopping there
// is both cheap and correct.
func descend(raw json.RawMessage, into *packageSet, depth int) {
	if depth <= 0 {
		return
	}

	switch jsonKind(raw) {
	case '{':
		var object orderedMap[json.RawMessage]
		if err := json.Unmarshal(raw, &object); err == nil {
			scanForDependencies(&object, into, depth)
		}
	case '[':
		var elements []json.RawMessage
		if err := json.Unmarshal(raw, &elements); err == nil {
			for _, element := range elements {
				descend(element, into, depth-1)
			}
		}
	}
}

// dependencyVersion reads the version out of a dependency's value, which
// project.json allows to be either a bare version or an object carrying one.
// Anything with no version at all becomes "unknown" rather than empty, so the
// package still appears in the graph and is visibly unversioned.
func dependencyVersion(raw json.RawMessage) string {
	switch jsonKind(raw) {
	case '"':
		var version string
		if err := json.Unmarshal(raw, &version); err == nil {
			return version
		}
	case '{':
		var object struct {
			Version json.RawMessage `json:"version"`
		}
		if err := json.Unmarshal(raw, &object); err == nil && len(object.Version) > 0 {
			return dependencyVersion(object.Version)
		}
	case '[', 'n':
		// An array or null carries nothing to read.
	default:
		// A number or boolean is reported as written, as upstream's toString
		// would.
		return strings.TrimSpace(string(raw))
	}

	return unknownVersion
}

// projectJSONRoot reads the project name and version a project.json may carry.
// snyk-nuget-plugin looks for them under `project`, the shape project.assets.json
// uses; real project.json files almost never have it.
func projectJSONRoot(doc *orderedMap[json.RawMessage]) (name, version string) {
	raw, ok := doc.Get("project")
	if !ok {
		return "", ""
	}

	var project struct {
		Version string `json:"version"`
		Restore struct {
			ProjectName string `json:"projectName"`
		} `json:"restore"`
	}

	if err := json.Unmarshal(raw, &project); err != nil {
		return "", ""
	}

	return project.Restore.ProjectName, project.Version
}

// packageSet accumulates packages keyed by name while keeping the order they
// were first seen in, the way assigning to a JavaScript object does: a repeated
// name keeps its original position, whatever happens to its version.
//
// Names are matched case-sensitively. Unlike project.assets.json, nothing on
// this path folds case: snyk-nuget-plugin indexes these by plain object key.
type packageSet struct {
	packages []declaredPackage
	index    map[string]int
}

func newPackageSet() *packageSet {
	return &packageSet{index: make(map[string]int)}
}

// set inserts a package, or overwrites the version of one already present.
func (p *packageSet) set(name, version string) {
	if at, exists := p.index[name]; exists {
		p.packages[at].version = version
		return
	}

	p.add(name, version)
}

// add inserts a package unless the name is already present, so the first
// declaration of a name wins.
func (p *packageSet) add(name, version string) {
	if _, exists := p.index[name]; exists {
		return
	}

	p.index[name] = len(p.packages)
	p.packages = append(p.packages, declaredPackage{name: name, version: version})
}

// replace overwrites the version of a package already present, and ignores one
// that is not. It never widens the set.
func (p *packageSet) replace(name, version string) {
	if at, exists := p.index[name]; exists {
		p.packages[at].version = version
	}
}

// get looks up a package by name.
func (p *packageSet) get(name string) (declaredPackage, bool) {
	at, exists := p.index[name]
	if !exists {
		return declaredPackage{}, false
	}

	return p.packages[at], true
}

// hasAny reports whether the object declares at least one of the given keys.
func hasAny(doc *orderedMap[json.RawMessage], keys ...string) bool {
	for _, key := range keys {
		if _, ok := doc.Get(key); ok {
			return true
		}
	}

	return false
}

// jsonKind reports the first meaningful byte of a JSON value, which is enough to
// tell object, array, string and null apart without decoding.
func jsonKind(raw json.RawMessage) byte {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return 0
	}

	return trimmed[0]
}
