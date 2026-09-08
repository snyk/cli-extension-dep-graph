package nuget

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// groupFrameworkPattern splits a .nuspec dependency group's moniker into its
// family and version, as snyk-nuget-plugin's targetFrameworkRegex does.
var groupFrameworkPattern = regexp.MustCompile(`([.a-zA-Z]+)([.0-9]+)`)

// nuspecFile is the subset of a .nuspec this resolver reads. Every level is a
// slice because the schema permits repeats and snyk-nuget-plugin walks them all.
type nuspecFile struct {
	Metadata []struct {
		Dependencies []nuspecDependencies `xml:"dependencies"`
	} `xml:"metadata"`
}

// nuspecDependencies is one <dependencies> element: framework-specific groups,
// plus any bare <dependency> children that apply to every framework.
type nuspecDependencies struct {
	Groups     []nuspecGroup      `xml:"group"`
	Standalone []nuspecDependency `xml:"dependency"`
}

// nuspecGroup is a <group>. An empty TargetFramework means the group applies to
// every framework.
type nuspecGroup struct {
	TargetFramework string             `xml:"targetFramework,attr"`
	Dependencies    []nuspecDependency `xml:"dependency"`
}

// nuspecDependency is one <dependency> element.
type nuspecDependency struct {
	ID string `xml:"id,attr"`
	// Version is a range as often as it is a version — "[1.0,2.0)" is legal
	// here. It is reported verbatim, as upstream does, and only ever reaches
	// the graph for a package that is not installed.
	Version string `xml:"version,attr"`
}

// nuspecDependencyList reads a package's own declared dependencies out of the
// .nuspec inside its installed .nupkg.
//
// This is the only source of transitive structure on this path, and it is not
// merely cosmetic: a .nuspec routinely names packages the manifest never lists,
// and those become part of the reported set.
//
// A package with no .nupkg on disk contributes nothing and is not an error —
// that is every package when a project was never restored. A .nupkg that is
// present but unreadable is an error, which leaves the whole manifest to the
// legacy resolver rather than reporting a set we know to be short.
func nuspecDependencyList(packagesFolder string, pkg declaredPackage, framework targetFramework) ([]declaredPackage, error) {
	path := filepath.Join(packageDir(packagesFolder, pkg), pkg.name+"."+pkg.version+nupkgExt)

	archive, err := zip.OpenReader(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, snykecosystems.NewUnprocessableFileError(
			fmt.Sprintf("Could not read the package archive for %s %s. "+
				"Restore the packages folder again, or pass --packages-folder to point at a complete one.",
				pkg.name, pkg.version),
			snyk_errors.WithCause(err),
		)
	}
	defer archive.Close()

	data, ok, err := readNuspec(&archive.Reader)
	if err != nil {
		return nil, snykecosystems.NewUnprocessableFileError(
			fmt.Sprintf("Could not read the .nuspec inside the package archive for %s %s.", pkg.name, pkg.version),
			snyk_errors.WithCause(err),
		)
	}

	// A .nupkg with no .nuspec is not a NuGet package. The package is left
	// childless rather than failing the manifest: it is still installed, and
	// its own entry in the graph is what a vulnerability is matched against.
	if !ok {
		return nil, nil
	}

	var doc nuspecFile
	if err := decodeXML(data, &doc); err != nil {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Could not parse the .nuspec for %s %s as XML.", pkg.name, pkg.version),
			snyk_errors.WithCause(err),
		)
	}

	// <metadata> is where a .nuspec keeps everything, dependencies included, so
	// a file without one tells us nothing about this package rather than
	// telling us it has none. Reporting the project anyway would quietly drop
	// whatever it does depend on — snyk-nuget-plugin's assertNuspecSchema fails
	// the scan here, and failing the manifest leaves the legacy resolver to do
	// exactly that.
	if len(doc.Metadata) == 0 {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("The .nuspec for %s %s has no <metadata> section, so it is not a valid package descriptor.",
				pkg.name, pkg.version),
		)
	}

	var children []declaredPackage

	for _, metadata := range doc.Metadata {
		for _, dependencies := range metadata.Dependencies {
			// Upstream's order, and it is worth keeping: the graph dedups, but
			// which entry for a package is seen first decides what version is
			// reported for it.
			if group, ok := matchingGroup(dependencies.Groups, framework); ok {
				children = append(children, asDeclared(group.Dependencies)...)
			}

			for _, group := range dependencies.Groups {
				if group.TargetFramework == "" {
					children = append(children, asDeclared(group.Dependencies)...)
				}
			}

			children = append(children, asDeclared(dependencies.Standalone)...)
		}
	}

	return children, nil
}

// matchingGroup picks the framework-specific dependency group that applies,
// mirroring snyk-nuget-plugin's extractDepsForTargetFramework.
//
// In practice it almost never matches anything. The comparison is between the
// long framework name toReadableFramework produces (".NETFramework") and the
// family parsed out of the group's own moniker ("net", for `net45`), which are
// equal only when the .nuspec spells the long form — as some older packages do.
// Everything a modern .nupkg declares per framework is therefore skipped, and
// what lands comes from the framework-agnostic groups instead. Comparing the
// short forms would report packages the CLI does not report today.
func matchingGroup(groups []nuspecGroup, framework targetFramework) (nuspecGroup, bool) {
	type candidate struct {
		family  string
		version string
		group   nuspecGroup
	}

	var candidates []candidate

	for _, group := range groups {
		parts := groupFrameworkPattern.FindStringSubmatch(group.TargetFramework)
		if parts == nil {
			continue
		}

		candidates = append(candidates, candidate{family: parts[1], version: parts[2], group: group})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].family != candidates[j].family {
			return candidates[i].family > candidates[j].family
		}

		// Highest version first. A moniker version that is not a number —
		// "4.5.1" is not — leaves the pair in the order the file declared them,
		// which is what upstream's NaN comparison amounts to.
		left, leftErr := strconv.ParseFloat(candidates[i].version, 64)
		right, rightErr := strconv.ParseFloat(candidates[j].version, 64)
		if leftErr != nil || rightErr != nil {
			return false
		}

		return left > right
	})

	for _, c := range candidates {
		// A string comparison, as upstream's is: "45" >= "4.5" holds.
		if framework.name == c.family && framework.version >= c.version {
			return c.group, true
		}
	}

	return nuspecGroup{}, false
}

// asDeclared converts .nuspec dependency elements, dropping any with no id.
func asDeclared(dependencies []nuspecDependency) []declaredPackage {
	var declared []declaredPackage

	for _, dependency := range dependencies {
		if dependency.ID == "" {
			continue
		}

		declared = append(declared, declaredPackage{name: dependency.ID, version: dependency.Version})
	}

	return declared
}

// readNuspec returns the contents of the first .nuspec in the archive, in the
// order the archive lists its entries.
func readNuspec(archive *zip.Reader) (content []byte, found bool, err error) {
	for _, file := range archive.File {
		if !strings.EqualFold(filepath.Ext(file.Name), nuspecExt) {
			continue
		}

		content, err = readZipEntry(file)
		if err != nil {
			return nil, false, err
		}

		return content, true, nil
	}

	return nil, false, nil
}

func readZipEntry(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", file.Name, err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", file.Name, err)
	}

	return content, nil
}

// nuspecChildren reads every installed package's own dependencies, keyed by
// package name. A package that declares none — or whose .nupkg is not on disk —
// is simply absent.
func nuspecChildren(installed *packageSet, packagesFolder string, framework targetFramework) (map[string][]declaredPackage, error) {
	children := make(map[string][]declaredPackage)

	for _, pkg := range installed.packages {
		declared, err := nuspecDependencyList(packagesFolder, pkg, framework)
		if err != nil {
			return nil, err
		}

		if declared != nil {
			children[pkg.name] = declared
		}
	}

	return children, nil
}
