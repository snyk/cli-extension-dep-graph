package nuget

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

func TestParseFolderName(t *testing.T) {
	tests := []struct {
		folder  string
		name    string
		version string
	}{
		{"jQuery.3.2.1", "jQuery", "3.2.1"},
		{"RestSharp.105.2.3", "RestSharp", "105.2.3"},
		// The split is at the first dot followed by digits, not the last dot,
		// which is the only reason a package with a dotted name survives it.
		{"Moment.js.2.20.1", "Moment.js", "2.20.1"},
		{"Microsoft.Web.Infrastructure.1.0.0.0", "Microsoft.Web.Infrastructure", "1.0.0.0"},
		{"Antlr.3.4.1.9004", "Antlr", "3.4.1.9004"},
		// No separating dot before the version, so the trailing 1 stays part of
		// the name. Upstream behaves the same way, and it is why an override is
		// keyed on an exact name match.
		{"FooBar1.2", "FooBar1", "2"},
		{"Newtonsoft.Json.13.0.3-beta1", "Newtonsoft.Json", "13.0.3-beta1"},
	}

	for _, test := range tests {
		t.Run(test.folder, func(t *testing.T) {
			name, version, ok := parseFolderName(test.folder)
			require.True(t, ok)

			assert.Equal(t, test.name, name)
			assert.Equal(t, test.version, version)
		})
	}
}

func TestParseFolderName_Rejects(t *testing.T) {
	// Everything a packages folder holds that is not an installed package: the
	// repositories.config NuGet writes beside them, and a folder someone named
	// by hand.
	for _, folder := range []string{"repositories.config", "someLibraryWithoutAVersion", "", ".gitignore"} {
		t.Run(folder, func(t *testing.T) {
			_, _, ok := parseFolderName(folder)
			assert.False(t, ok)
		})
	}
}

func TestResolvePackagesFolder(t *testing.T) {
	manifest := filepath.Join("Solution", "Project", packagesConfigFile)

	// The manifest's grandparent, which is the classic layout: one packages
	// folder shared by every project in a solution.
	assert.Equal(t, filepath.Join("Solution", packagesFolderName), resolvePackagesFolder(manifest, ""))

	assert.Equal(t, "/elsewhere/packages", resolvePackagesFolder(manifest, "/elsewhere/packages"),
		"--packages-folder wins, which is how a project whose packages folder sits beside it is resolved at all")
}

func TestInstalledPackages_FolderWinsOnVersion(t *testing.T) {
	folder := t.TempDir()
	makePackageDirs(t, folder, "jQuery.3.2.1", "Moment.js.2.20.1")

	declared := []declaredPackage{{"jQuery", "1.9.1"}, {"Moment.js", "2.20.1"}}

	installed := installedPackages(context.Background(), logger.Nop(), declared, folder)

	// A packages.config that has drifted from its restore output is reported as
	// restored: the installed assembly is what would actually be exploited.
	assert.Equal(t, []declaredPackage{{"jQuery", "3.2.1"}, {"Moment.js", "2.20.1"}}, installed.packages)
}

func TestInstalledPackages_NeverWidensTheSet(t *testing.T) {
	folder := t.TempDir()
	makePackageDirs(t, folder, "jQuery.3.2.1", "NUnit.2.6.3")

	installed := installedPackages(context.Background(), logger.Nop(),
		[]declaredPackage{{"jQuery", "3.2.1"}}, folder)

	// Several projects commonly share one packages folder, so what is installed
	// there is not evidence that this project depends on it.
	assert.Equal(t, []declaredPackage{{"jQuery", "3.2.1"}}, installed.packages)
}

func TestInstalledPackages_KeepsManifestOrderAndFirstDeclaration(t *testing.T) {
	installed := installedPackages(context.Background(), logger.Nop(),
		[]declaredPackage{{"B", "1.0"}, {"A", "1.0"}, {"B", "2.0"}}, t.TempDir())

	assert.Equal(t, []declaredPackage{{"B", "1.0"}, {"A", "1.0"}}, installed.packages)
}

func TestInstalledPackages_NoFolder(t *testing.T) {
	declared := []declaredPackage{{"jQuery", "3.2.1"}}

	log := &recordingLogger{}
	installed := installedPackages(context.Background(), log, declared, filepath.Join(t.TempDir(), "absent"))

	// The usual case: a checkout that was never restored. A .NET Framework
	// manifest already lists its transitive dependencies, so the manifest's own
	// versions are a complete package set.
	assert.Equal(t, declared, installed.packages)
	assert.Empty(t, log.errs, "an unrestored project is ordinary, not a failure")
	assert.NotEmpty(t, log.debug)
}

// makePackageDirs creates installed-package directories inside a packages folder.
func makePackageDirs(t *testing.T, folder string, names ...string) {
	t.Helper()

	for _, name := range names {
		require.NoError(t, os.MkdirAll(filepath.Join(folder, name), 0o750))
	}
}
