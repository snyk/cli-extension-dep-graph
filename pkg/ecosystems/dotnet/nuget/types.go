package nuget

const (
	// projectAssetsFile is `dotnet restore` output for SDK-style
	// (PackageReference) projects: a fully resolved dependency set.
	projectAssetsFile = "project.assets.json"

	// packagesConfigFile is the .NET Framework manifest. It records no resolved
	// dependency set — just a flattened list of what NuGet installed.
	packagesConfigFile = "packages.config"

	// projectJSONFile is the pre-RTM .NET Core manifest. The CLI discovers it
	// (snyk/cli src/lib/detect.ts) but this resolver does not yet: CMPA-717.
	projectJSONFile = "project.json"

	// objDir is where `dotnet restore` writes project.assets.json. A target file
	// inside it describes the project one directory up.
	objDir = "obj"

	// packagesFolderName is the directory `nuget restore` installs into. Its
	// default location is derived from the manifest's path; --packages-folder
	// overrides it. See resolvePackagesFolder.
	packagesFolderName = "packages"

	// csprojExt is the only project file extension consulted for a target
	// framework. See csprojTargetFramework.
	csprojExt = ".csproj"
	nupkgExt  = ".nupkg"
	nuspecExt = ".nuspec"

	// defaultVersion roots a project whose manifest declares no version,
	// matching snyk-nuget-plugin.
	defaultVersion = "0.0.0"

	// filteredPackagePrefix drops `runtime` and `runtime.native.*` packages:
	// platform-specific runtime assets rather than dependencies a user can act
	// on. Matched case-sensitively against the declared name, as upstream does.
	filteredPackagePrefix = "runtime"

	// Target framework families whose `targets` key differs mechanically from
	// their project.frameworks key. See assetsFrameworkName.
	netstandardPrefix = "netstandard"
	netcoreappPrefix  = "netcoreapp"
	netPrefix         = "net"

	// maxNetFrameworkDigits bounds a .NET Framework moniker's compact version.
	// net481 is the longest that exists; the bound stops "net" rewriting
	// monikers from other families.
	maxNetFrameworkDigits = 3

	// A dependency edge closing a cycle becomes a childless node suffixed like
	// this and labeled, mirroring snyk-nuget-plugin's `<id>:pruned` nodes.
	prunedNodeSuffix = ":pruned"
	prunedLabelKey   = "pruned"
	prunedLabelValue = "true"
)

// targetFileNames lists every file name discovery matches.
var targetFileNames = []string{
	projectAssetsFile,
	packagesConfigFile,
}

// rootTargetFilePrecedence orders the manifests a single-project scan chooses
// between when a directory holds more than one, highest priority first. It
// mirrors the CLI's own DETECTABLE_FILES order (snyk/cli src/lib/detect.ts),
// which is what decides that a directory holding restore output alongside the
// manifest it was generated from is one project, not two.
var rootTargetFilePrecedence = []struct{ subdir, name string }{
	{objDir, projectAssetsFile},
	{"", projectAssetsFile},
	{"", packagesConfigFile},
}
