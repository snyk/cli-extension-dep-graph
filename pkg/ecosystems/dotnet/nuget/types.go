package nuget

const (
	// projectAssetsFile is `dotnet restore` output for SDK-style
	// (PackageReference) projects, and the only target file this plugin claims.
	projectAssetsFile = "project.assets.json"

	// packagesConfigFile and projectJSONFile are the .NET Framework manifests.
	// The CLI discovers them (snyk/cli src/lib/detect.ts) but this resolver does
	// not: they carry no resolved dependency set. Leaving them out of
	// targetFileNames is what makes those projects fall back to the legacy
	// resolver, which reports them exactly as it does today.
	packagesConfigFile = "packages.config"
	projectJSONFile    = "project.json"

	// objDir is where `dotnet restore` writes project.assets.json. A target file
	// inside it describes the project one directory up.
	objDir = "obj"

	// defaultVersion roots a project whose assets file declares no
	// project.version, matching snyk-nuget-plugin.
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
}
