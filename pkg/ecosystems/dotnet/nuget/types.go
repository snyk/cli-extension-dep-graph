package nuget

const (
	// projectAssetsFile is `dotnet restore` output for SDK-style
	// (PackageReference) projects: a fully resolved dependency set.
	projectAssetsFile = "project.assets.json"

	// packagesConfigFile and projectJSONFile are the older manifests, for
	// .NET Framework and for pre-RTM .NET Core respectively. Neither records a
	// resolved dependency set, so resolving one means reading the packages
	// folder that `nuget restore` populates beside it.
	packagesConfigFile = "packages.config"
	projectJSONFile    = "project.json"

	// objDir is where `dotnet restore` writes project.assets.json. A target file
	// inside it describes the project one directory up.
	objDir = "obj"

	// slnxExtension is the XML solution format that replaces the text `.sln` from
	// Visual Studio 17.14 / .NET 9 onwards. It is not a manifest: passed to
	// --file, a solution selects the projects it holds.
	slnxExtension = ".slnx"

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

	// unknownVersion stands in for a project.json dependency declared with no
	// version at all, as snyk-nuget-plugin's project-json-parser does.
	unknownVersion = "unknown"

	// maxProjectJSONDepth bounds how deep the search for dependency groups
	// goes, so that a small file nested pathologically deep cannot cost a
	// scan seconds of work. See descend for the measurements, and for why the
	// bound only bites because that walk decodes one level at a time.
	maxProjectJSONDepth = 64

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
	projectJSONFile,
}

// rootTargetFilePrecedence orders the manifests a single-project scan chooses
// between when a directory holds more than one, highest priority first. It
// mirrors the CLI's own DETECTABLE_FILES order (snyk/cli src/lib/detect.ts),
// which is what decides today that a directory holding both packages.config and
// project.assets.json is one project, not two.
//
// project.json is absent deliberately: the CLI lists it in AUTO_DETECTABLE_FILES
// but not DETECTABLE_FILES, so a bare scan of a directory holding only a
// project.json reports no supported target file. It stays reachable through
// --file and --all-projects.
var rootTargetFilePrecedence = []struct{ subdir, name string }{
	{objDir, projectAssetsFile},
	{"", projectAssetsFile},
	{"", packagesConfigFile},
}
