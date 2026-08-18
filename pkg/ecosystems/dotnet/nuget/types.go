package nuget

const (
	// Target files this plugin recognizes as identifying a .NET project.
	//
	// Taken from what the CLI discovers today, in snyk/cli's
	// src/lib/detect.ts: SUPPORTED_TARGET_FILES (the --file allowlist,
	// lines 29-32) holds obj/project.assets.json, project.assets.json and
	// packages.config; AUTO_DETECTABLE_FILES (lines 50-53, walked for
	// --all-projects via src/lib/plugins/get-deps-from-plugin.ts) holds
	// packages.config, project.json and project.assets.json.
	//
	// Note what is deliberately absent. *.csproj / *.vbproj / *.fsproj and
	// *.sln are not discoverable target files: snyk-nuget-plugin reads project
	// files internally to resolve target frameworks and the project name, but
	// discovery keys on restore output and config files only. Matching that
	// matters — recognizing project files here would make this resolver claim
	// projects the current resolver never would.
	//
	// paket.dependencies is absent for a different reason: detect.ts routes it
	// to a separate paket plugin (src/lib/plugins/index.ts), not to nuget.
	projectAssetsFile  = "project.assets.json"
	packagesConfigFile = "packages.config"
	projectJSONFile    = "project.json"

	// objDir is where `dotnet restore` writes project.assets.json. A target
	// file inside it describes the project one directory up, matching
	// getRootName in snyk-nuget-plugin's lib/nuget-parser/index.ts:86-91.
	objDir = "obj"

	// placeholderTargetRuntime stands in for the project's target framework.
	// .NET results carry one — the legacy resolver reports values like
	// "net6.0" — and the platform uses it to tell a project's frameworks
	// apart. Reading the real value means parsing the project or its restore
	// output, which this placeholder resolver does not do, so report an
	// obviously non-framework value rather than inventing a plausible one.
	placeholderTargetRuntime = "unknown"

	// fallbackRootName names the root package when the target file's directory
	// cannot name the project (a filesystem or volume root). It matches the
	// default the dep-graph builder itself uses for an unnamed root package.
	fallbackRootName = "_root"

	// defaultVersion is the root package version. No .NET target file carries a
	// project version that is knowable without resolving the project, and the
	// CLI's current static analysis reports the same value — see
	// `version: '0.0.0'` at lib/nuget-parser/index.ts:423 in
	// snyk-nuget-plugin, which roots every manifest type it supports.
	defaultVersion = "0.0.0"
)

// targetFileNames lists every file name discovery matches. All are exact names
// rather than globs, so they double as basename matches for include patterns.
var targetFileNames = []string{
	projectAssetsFile,
	packagesConfigFile,
	projectJSONFile,
}
