package nuget

import (
	"fmt"
	"os"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// declaredPackage is one dependency as a manifest names it.
type declaredPackage struct {
	name    string
	version string
}

// frameworkManifest is what a packages.config contributes to resolution.
type frameworkManifest struct {
	// packages is every dependency the manifest declares, in document order.
	// packages.config lists the whole flattened set, transitive dependencies
	// included.
	packages []declaredPackage

	// frameworkHints are the targetFramework attributes NuGet writes onto the
	// entries it installs, and are consulted only when the project has no
	// .csproj to read.
	frameworkHints []string
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

// packageSet accumulates packages keyed by name while keeping the order they
// were first seen in, the way assigning to a JavaScript object does: a repeated
// name keeps its original position.
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
