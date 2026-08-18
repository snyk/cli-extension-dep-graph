package nuget

const (
	// Target files this plugin recognizes as identifying a .NET project.
	//
	// The project-file globs and packages.config identify a project whose
	// dependencies are yet to be resolved; project.assets.json is `dotnet
	// restore` output and is what the CLI's current static analysis parses.
	// Kept as a single set so discovery matches the target files the
	// TypeScript snyk-nuget-plugin accepts today.
	csprojGlob         = "*.csproj"
	vbprojGlob         = "*.vbproj"
	fsprojGlob         = "*.fsproj"
	solutionGlob       = "*.sln"
	packagesConfigFile = "packages.config"
	projectAssetsFile  = "project.assets.json"

	// defaultVersion is the root package version. No .NET target file carries a
	// project version that is knowable without resolving the project, and the
	// CLI's current static analysis reports the same value — see `version:
	// '0.0.0'` in snyk-nuget-plugin's lib/nuget-parser/index.ts, which roots
	// every manifest type it supports.
	defaultVersion = "0.0.0"
)

// targetFileGlobs lists every pattern discovery matches when scanning a tree.
// discovery.FindFiles matches include globs against the basename only, so
// plain filenames act as exact-basename matches.
var targetFileGlobs = []string{
	csprojGlob,
	vbprojGlob,
	fsprojGlob,
	solutionGlob,
	packagesConfigFile,
	projectAssetsFile,
}

// buildOutputDirs are excluded when scanning a tree. .NET writes build output
// and restore artifacts here; discovery.WithCommonExcludes only covers
// ".build" and "node_modules". A project.assets.json inside obj/ is still
// reachable when the user points --file directly at it.
var buildOutputDirs = []string{"bin", "obj"}
