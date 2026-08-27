package nuget

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// folderVersionPattern matches the version an installed package's folder name
// ends with, starting at the leftmost `.` that is followed by digits.
//
// Ported from snyk-nuget-plugin's extractFromDotVersionNotation. Its two
// lookaheads only assert that the match begins at a non-space `.`, which the
// pattern itself already requires, so they are dropped rather than worked
// around — Go's regexp has no lookahead.
var folderVersionPattern = regexp.MustCompile(`(\.\d+)+((-?\w+\.?\d*)|(\+?[0-9a-f]{5,40}))?`)

// resolvePackagesFolder decides where `nuget restore` installed this project's
// packages.
//
// The default is the manifest's grandparent directory, which is right for the
// classic layout where a solution keeps one packages folder beside its projects
// (Solution/packages and Solution/Project/packages.config) and wrong whenever
// the folder sits beside the manifest instead. That is snyk-nuget-plugin's
// default, quirk included, and --packages-folder is how both it and the CLI's
// own tests work around it.
func resolvePackagesFolder(manifestPath, override string) string {
	if override != "" {
		return override
	}

	return filepath.Join(filepath.Dir(manifestPath), "..", packagesFolderName)
}

// installedPackages reconciles what a manifest declares against what is
// actually installed, mirroring snyk-nuget-plugin's scanInstalled.
//
// The folder wins on version: a project whose packages.config has drifted from
// its restore output is reported as restored, not as written. It never widens
// the set — a package present only in the folder is not necessarily a
// dependency of this project, since several projects commonly share one folder.
//
// A missing or unreadable folder is the common case rather than a failure: most
// scans run on a checkout that was never restored, and a .NET Framework
// manifest lists its transitive dependencies anyway, so the manifest's own
// versions are already a complete package set.
func installedPackages(
	ctx context.Context,
	log logger.Logger,
	declared []declaredPackage,
	packagesFolder string,
) *packageSet {
	installed := newPackageSet()
	for _, pkg := range declared {
		installed.add(pkg.name, pkg.version)
	}

	entries, err := os.ReadDir(packagesFolder)
	if err != nil {
		log.Debug(ctx, "Resolving .NET packages from the manifest alone: no readable packages folder",
			logger.Attr(logFieldPackagesFolder, packagesFolder), logger.Err(err))

		return installed
	}

	for _, entry := range entries {
		name, version, ok := parseFolderName(entry.Name())
		if !ok {
			continue
		}

		installed.replace(name, version)
	}

	return installed
}

// parseFolderName splits an installed package's folder name into name and
// version, reporting false for a name that carries no version at all.
//
// The split is at the leftmost `.` followed by digits, so `Moment.js.2.20.1`
// yields `Moment.js` and `2.20.1`, and `FooBar1.2` yields `FooBar1` and `2`.
func parseFolderName(folder string) (name, version string, ok bool) {
	at := folderVersionPattern.FindStringIndex(folder)

	// at[0] == 0 means the name is nothing but a version, which no package is.
	if len(at) < 2 || at[0] == 0 {
		return "", "", false
	}

	// The match begins at the separating dot, which belongs to neither half.
	return folder[:at[0]], folder[at[0]+1 : at[1]], true
}

// packageDir is where a package's own files were installed.
func packageDir(packagesFolder string, pkg declaredPackage) string {
	return filepath.Join(packagesFolder, pkg.name+"."+pkg.version)
}
