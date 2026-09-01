package nuget

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const swaggerNuspec = `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd">
  <metadata>
    <id>Swagger.Net</id>
    <version>0.5.5</version>
    <dependencies>
      <dependency id="WebActivator" version="1.5.1" />
    </dependencies>
  </metadata>
</package>`

func TestNuspecDependencyList_BareDependencies(t *testing.T) {
	folder := t.TempDir()
	pkg := declaredPackage{"Swagger.Net", "0.5.5"}
	writeNupkg(t, folder, pkg, zipEntry{"Swagger.Net" + nuspecExt, []byte(swaggerNuspec)})

	children, err := nuspecDependencyList(folder, pkg, framework(t, "net45"))
	require.NoError(t, err)

	// WebActivator appears in no packages.config. It reaches the reported set
	// only through this file, which is why reading .nupkg archives is not
	// optional polish.
	assert.Equal(t, []declaredPackage{{"WebActivator", "1.5.1"}}, children)
}

func TestNuspecDependencyList_Groups(t *testing.T) {
	tests := []struct {
		name         string
		dependencies string
		moniker      string
		want         []declaredPackage
	}{
		{
			name:    "a group with no targetFramework applies to everything",
			moniker: "net45",
			dependencies: `<group>
        <dependency id="Everywhere" version="1.0" />
      </group>`,
			want: []declaredPackage{{"Everywhere", "1.0"}},
		},
		{
			// The quirk that decides what a modern .nupkg contributes. The
			// comparison is between ".NETFramework" and the "net" parsed out of
			// this group's own moniker, so it can never hold. Matching short
			// forms here would report packages the CLI does not report today.
			name:    "a short-form framework group never matches",
			moniker: "net45",
			dependencies: `<group targetFramework="net45">
        <dependency id="Skipped" version="1.0" />
      </group>`,
		},
		{
			name:    "a long-form framework group does match",
			moniker: "net45",
			dependencies: `<group targetFramework=".NETFramework4.5">
        <dependency id="Matched" version="1.0" />
      </group>`,
			want: []declaredPackage{{"Matched", "1.0"}},
		},
		{
			name:    "the highest applicable group wins",
			moniker: "net45",
			dependencies: `<group targetFramework=".NETFramework4.0">
        <dependency id="Old" version="1.0" />
      </group>
      <group targetFramework=".NETFramework4.5">
        <dependency id="New" version="1.0" />
      </group>`,
			want: []declaredPackage{{"New", "1.0"}},
		},
		{
			name:    "a group for another family is ignored",
			moniker: "net45",
			dependencies: `<group targetFramework=".NETStandard2.0">
        <dependency id="Standard" version="1.0" />
      </group>`,
		},
		{
			name:    "the framework group comes before the framework-agnostic one",
			moniker: "net45",
			dependencies: `<group>
        <dependency id="Everywhere" version="1.0" />
      </group>
      <group targetFramework=".NETFramework4.5">
        <dependency id="Matched" version="1.0" />
      </group>
      <dependency id="Bare" version="1.0" />`,
			want: []declaredPackage{{"Matched", "1.0"}, {"Everywhere", "1.0"}, {"Bare", "1.0"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			folder := t.TempDir()
			pkg := declaredPackage{"Pkg", "1.0.0"}
			writeNupkg(t, folder, pkg, zipEntry{"Pkg" + nuspecExt, []byte(nuspecWith(test.dependencies))})

			children, err := nuspecDependencyList(folder, pkg, framework(t, test.moniker))
			require.NoError(t, err)
			assert.Equal(t, test.want, children)
		})
	}
}

// The version comparison is a string comparison, so how a project spells its
// framework decides whether a group applies. A v4.5 project is below
// .NETFramework4.6 and skips the group; a net45 project compares "45" against
// "4.6", which is above it, and takes the group instead. Upstream compares the
// same two strings the same way.
func TestNuspecDependencyList_VersionComparisonIsTextual(t *testing.T) {
	dependencies := `<group targetFramework=".NETFramework4.6">
        <dependency id="Higher" version="1.0" />
      </group>`

	for moniker, want := range map[string][]declaredPackage{
		"v4.5":  nil,
		"net45": {{"Higher", "1.0"}},
	} {
		t.Run(moniker, func(t *testing.T) {
			folder := t.TempDir()
			pkg := declaredPackage{"Pkg", "1.0.0"}
			writeNupkg(t, folder, pkg, zipEntry{"Pkg" + nuspecExt, []byte(nuspecWith(dependencies))})

			children, err := nuspecDependencyList(folder, pkg, framework(t, moniker))
			require.NoError(t, err)
			assert.Equal(t, want, children)
		})
	}
}

func TestNuspecDependencyList_UTF16(t *testing.T) {
	folder := t.TempDir()
	pkg := declaredPackage{"Swagger.Net", "0.5.5"}

	// Real .nupkg archives from this era carry UTF-16 .nuspec files —
	// Swagger.Net 0.5.5 among them.
	utf16Nuspec := `<?xml version="1.0" encoding="utf-16"?>
<package><metadata><dependencies>
  <dependency id="WebActivator" version="1.5.1" />
</dependencies></metadata></package>`
	writeNupkg(t, folder, pkg, zipEntry{"Swagger.Net" + nuspecExt, utf16LE(utf16Nuspec)})

	children, err := nuspecDependencyList(folder, pkg, framework(t, "net45"))
	require.NoError(t, err)
	assert.Equal(t, []declaredPackage{{"WebActivator", "1.5.1"}}, children)
}

func TestNuspecDependencyList_NoArchive(t *testing.T) {
	children, err := nuspecDependencyList(t.TempDir(), declaredPackage{"Absent", "1.0.0"}, framework(t, "net45"))

	// Every package looks like this when a project was never restored, which is
	// most scans. It has to stay an ordinary outcome rather than a failure.
	require.NoError(t, err)
	assert.Nil(t, children)
}

func TestNuspecDependencyList_ArchiveWithoutNuspec(t *testing.T) {
	folder := t.TempDir()
	pkg := declaredPackage{"Pkg", "1.0.0"}
	writeNupkg(t, folder, pkg, zipEntry{"lib/net45/Pkg.dll", []byte("not a nuspec")})

	children, err := nuspecDependencyList(folder, pkg, framework(t, "net45"))
	require.NoError(t, err, "the package is still installed; only its dependencies are unknown")
	assert.Nil(t, children)
}

func TestNuspecDependencyList_UnreadableArchive(t *testing.T) {
	folder := t.TempDir()
	pkg := declaredPackage{"Pkg", "1.0.0"}

	dir := packageDir(folder, pkg)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Pkg.1.0.0"+nupkgExt), []byte("not a zip"), 0o600))

	// A truncated archive means we cannot know what this package pulls in, and
	// reporting the rest of the project would quietly omit those packages. The
	// caller turns this into a fall-through to the legacy resolver.
	_, err := nuspecDependencyList(folder, pkg, framework(t, "net45"))
	require.Error(t, err)
	assert.NotEmpty(t, detailOf(t, err))
}

func TestNuspecChildren_SkipsPackagesWithNothingToSay(t *testing.T) {
	folder := t.TempDir()
	withDeps := declaredPackage{"Swagger.Net", "0.5.5"}
	writeNupkg(t, folder, withDeps, zipEntry{"Swagger.Net" + nuspecExt, []byte(swaggerNuspec)})

	installed := newPackageSet()
	installed.add(withDeps.name, withDeps.version)
	installed.add("Antlr", "3.4.1.9004")

	children, err := nuspecChildren(installed, folder, framework(t, "net45"))
	require.NoError(t, err)

	assert.Equal(t, map[string][]declaredPackage{
		"Swagger.Net": {{"WebActivator", "1.5.1"}},
	}, children)
}

// nuspecWith wraps a <dependencies> body in the rest of a .nuspec.
func nuspecWith(dependencies string) string {
	return `<?xml version="1.0"?>
<package>
  <metadata>
    <id>Pkg</id>
    <dependencies>
      ` + dependencies + `
    </dependencies>
  </metadata>
</package>`
}

// framework decomposes a moniker for a test, failing if it is one the resolver
// does not recognize.
func framework(t *testing.T, moniker string) targetFramework {
	t.Helper()

	decomposed, ok := toReadableFramework(moniker)
	require.True(t, ok, "%s should be a recognized moniker", moniker)

	return decomposed
}

type zipEntry struct {
	name    string
	content []byte
}

// writeNupkg builds an installed package directory holding a .nupkg with the
// given entries, the layout `nuget restore` leaves behind.
func writeNupkg(t *testing.T, packagesFolder string, pkg declaredPackage, entries ...zipEntry) {
	t.Helper()

	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)

	for _, entry := range entries {
		writer, err := archive.Create(entry.name)
		require.NoError(t, err)
		_, err = writer.Write(entry.content)
		require.NoError(t, err)
	}

	require.NoError(t, archive.Close())

	dir := packageDir(packagesFolder, pkg)
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, pkg.name+"."+pkg.version+nupkgExt), buf.Bytes(), 0o600))
}

// <metadata> holds everything a .nuspec says, dependencies included, so a file
// without one tells us nothing about the package. Treating that as "declares no
// dependencies" would report the project while silently dropping whatever it
// depends on; snyk-nuget-plugin fails the scan here instead.
func TestNuspecDependencyList_NuspecWithoutMetadata(t *testing.T) {
	folder := t.TempDir()
	pkg := declaredPackage{"Pkg", "1.0.0"}
	writeNupkg(t, folder, pkg, zipEntry{"Pkg" + nuspecExt, []byte(`<?xml version="1.0"?><package></package>`)})

	_, err := nuspecDependencyList(folder, pkg, framework(t, "net45"))
	require.Error(t, err)
	assert.NotEmpty(t, detailOf(t, err))
}
