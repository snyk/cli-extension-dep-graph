package depgraph

import "github.com/spf13/pflag"

const (
	flagSetName = "depgraph"
)

const (
	FlagFailFast                      = "fail-fast"
	FlagAllProjects                   = "all-projects"
	FlagDev                           = "dev"
	FlagExclude                       = "exclude"
	FlagFile                          = "file"
	FlagDetectionDepth                = "detection-depth"
	FlagPruneRepeatedSubdependencies  = "prune-repeated-subdependencies"
	FlagMavenAggregateProject         = "maven-aggregate-project"
	FlagMavenSkipWrapper              = "maven-skip-wrapper" //nolint:gosec // Not a credential, this is a CLI flag name
	FlagScanUnmanaged                 = "scan-unmanaged"
	FlagScanAllUnmanaged              = "scan-all-unmanaged"
	FlagSubProject                    = "sub-project"
	FlagGradleSubProject              = "gradle-sub-project"
	FlagGradleNormalizeDeps           = "gradle-normalize-deps"
	FlagAllSubProjects                = "all-sub-projects"
	FlagConfigurationMatching         = "configuration-matching"
	FlagConfigurationAttributes       = "configuration-attributes"
	FlagInitScript                    = "init-script"
	FlagYarnWorkspaces                = "yarn-workspaces"
	FlagPythonCommand                 = "command"
	FlagPythonSkipUnresolved          = "skip-unresolved"
	FlagPythonPackageManager          = "package-manager"
	FlagStrictOutOfSync               = "strict-out-of-sync"
	FlagNugetAssetsProjectName        = "assets-project-name"
	FlagNugetPkgsFolder               = "packages-folder"
	FlagUnmanagedMaxDepth             = "max-depth"
	FlagIncludeProvenance             = "include-provenance"
	FlagUseSBOMResolution             = "use-sbom-resolution"
	FlagPrintGraph                    = "print-graph"
	FlagJSONLOutput                   = "jsonl-output"
	FlagPrintEffectiveGraph           = "effective-graph"
	FlagPrintEffectiveGraphWithErrors = "effective-graph-with-errors"
	FlagPrintErrors                   = "print-errors"
	FlagDotnetRuntimeResolution       = "dotnet-runtime-resolution"
	FlagDotnetTargetFramework         = "dotnet-target-framework"
	FlagUvWorkspacePackages           = "internal-uv-workspace-packages"
	FlagForceSingleGraph              = "force-single-graph"
)

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(flagSetName, pflag.ExitOnError)

	flagSet.Bool(FlagFailFast, false, "Fail fast when scanning all projects")
	flagSet.Bool(FlagAllProjects, false, "Enable all projects")
	flagSet.Bool(FlagDev, false, "Include dev dependencies")
	flagSet.String(FlagFile, "", "Input file")
	flagSet.String(FlagDetectionDepth, "", "Detection depth")
	flagSet.BoolP(FlagPruneRepeatedSubdependencies, "p", false, "Prune repeated sub-dependencies")
	flagSet.Bool(FlagMavenAggregateProject, false, "Ensure all modules are resolvable by the Maven reactor.")
	flagSet.Bool(FlagMavenSkipWrapper, false, "Use system Maven instead of the Maven wrapper.")
	flagSet.Bool(FlagScanUnmanaged, false, "Specify an individual JAR, WAR, or AAR file.")
	flagSet.Bool(FlagScanAllUnmanaged, false, "Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder.")
	flagSet.String(FlagSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.String(FlagGradleSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.Bool(FlagGradleNormalizeDeps, false, "Normalize Gradle dependencies.")
	flagSet.Bool(FlagAllSubProjects, false, "Test all sub-projects in a multi-project build.")
	flagSet.String(FlagConfigurationMatching, "", "Resolve dependencies using only configuration(s) that match the specified Java regular expression.")
	flagSet.String(FlagConfigurationAttributes, "", "Select certain values of configuration attributes to install and resolve dependencies.")
	flagSet.String(FlagInitScript, "", "Use for projects that contain a Gradle initialization script.")
	flagSet.Bool(FlagYarnWorkspaces, false, "Detect and scan Yarn Workspaces only when a lockfile is in the root.")
	flagSet.String(FlagPythonCommand, "", "Indicate which specific Python commands to use based on the Python version.")
	flagSet.String(FlagPythonSkipUnresolved, "", "Skip Python packages that cannot be found in the environment.")
	flagSet.String(FlagPythonPackageManager, "", `Add --package-manager=pip to your command if the file name is not "requirements.txt".`)
	flagSet.String(FlagStrictOutOfSync, "true", "Prevent testing out-of-sync lockfiles.")
	flagSet.Bool(FlagNugetAssetsProjectName, false,
		"When you are monitoring a .NET project using NuGet PackageReference uses the project name in project.assets.json if found.")
	flagSet.String(FlagNugetPkgsFolder, "", "Specify a custom path to the packages folder when using NuGet.")
	flagSet.Int(FlagUnmanagedMaxDepth, 0, "Specify the maximum level of archive extraction for unmanaged scanning.")
	flagSet.Bool(FlagIncludeProvenance, false, "Include checksums in purl to support package provenance.")
	flagSet.Bool(FlagUseSBOMResolution, false, "Use SBOM resolution instead of legacy CLI.")
	flagSet.Bool(FlagPrintGraph, false, "Return the dependency graph.")
	flagSet.Bool(FlagJSONLOutput, false, "Return dependency graph output as JSONL when supported.")
	flagSet.Bool(FlagPrintEffectiveGraph, false, "Return the pruned dependency graph.")
	flagSet.Bool(FlagPrintEffectiveGraphWithErrors, false, "Return errors in the pruned dependency graph output.")
	flagSet.Bool(FlagPrintErrors, false, "Return errors in dependency graph output.")
	flagSet.Bool(FlagDotnetRuntimeResolution, false, "Required. You must use this option when you test .NET projects using Runtime Resolution Scanning.")
	flagSet.String(FlagDotnetTargetFramework, "",
		"Optional. You may use this option if your solution contains multiple <TargetFramework> directives. "+
			"If you do not specify the option --dotnet-target-framework, all supported Target Frameworks will be scanned.")
	flagSet.Bool(FlagUvWorkspacePackages, false, "Include all uv workspace packages in the dependency graph output")
	flagSet.Bool(FlagForceSingleGraph, false, "Prevent splitting the dependency graph within an ecosystem.")

	return flagSet
}
