package depgraph

import (
	"github.com/spf13/pflag"

	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
)

const (
	flagSetName = "depgraph"
)

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(flagSetName, pflag.ExitOnError)

	flagSet.Bool(workflow.FlagFailFast, false, "Fail fast when scanning all projects")
	flagSet.Bool(workflow.FlagAllProjects, false, "Enable all projects")
	flagSet.Bool(workflow.FlagPrintOutputJsonlWithErrors, false, "Print output JSONL with errors")
	flagSet.Bool(workflow.FlagDev, false, "Include dev dependencies")
	flagSet.String(workflow.FlagFile, "", "Input file")
	flagSet.String(workflow.FlagDetectionDepth, "", "Detection depth")
	flagSet.BoolP(workflow.FlagPruneRepeatedSubdependencies, "p", false, "Prune repeated sub-dependencies")
	flagSet.Bool(workflow.FlagMavenAggregateProject, false, "Ensure all modules are resolvable by the Maven reactor.")
	flagSet.Bool(workflow.FlagMavenSkipWrapper, false, "Use system Maven instead of the Maven wrapper.")
	flagSet.Bool(workflow.FlagScanUnmanaged, false, "Specify an individual JAR, WAR, or AAR file.")
	flagSet.Bool(workflow.FlagScanAllUnmanaged, false, "Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder.")
	flagSet.String(workflow.FlagSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.String(workflow.FlagGradleSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.Bool(workflow.FlagGradleNormalizeDeps, false, "Normalize Gradle dependencies.")
	flagSet.Bool(workflow.FlagAllSubProjects, false, "Test all sub-projects in a multi-project build.")
	flagSet.String(workflow.FlagConfigurationMatching, "", "Resolve dependencies using only configuration(s) that match the specified Java regular expression.")
	flagSet.String(workflow.FlagConfigurationAttributes, "", "Select certain values of configuration attributes to install and resolve dependencies.")
	flagSet.String(workflow.FlagInitScript, "", "Use for projects that contain a Gradle initialization script.")
	flagSet.Bool(workflow.FlagYarnWorkspaces, false, "Detect and scan Yarn Workspaces only when a lockfile is in the root.")
	flagSet.String(workflow.FlagPythonCommand, "", "Indicate which specific Python commands to use based on the Python version.")
	flagSet.String(workflow.FlagPythonSkipUnresolved, "", "Skip Python packages that cannot be found in the environment.")
	flagSet.String(workflow.FlagPythonPackageManager, "", `Add --package-manager=pip to your command if the file name is not "requirements.txt".`)
	flagSet.String(workflow.FlagStrictOutOfSync, "true", "Prevent testing out-of-sync lockfiles.")
	flagSet.Bool(workflow.FlagNugetAssetsProjectName, false,
		"When you are monitoring a .NET project using NuGet PackageReference uses the project name in project.assets.json if found.")
	flagSet.String(workflow.FlagNugetPkgsFolder, "", "Specify a custom path to the packages folder when using NuGet.")
	flagSet.Int(workflow.FlagUnmanagedMaxDepth, 0, "Specify the maximum level of archive extraction for unmanaged scanning.")
	flagSet.Bool(workflow.FlagIncludeProvenance, false, "Include checksums in purl to support package provenance.")
	flagSet.Bool(workflow.FlagUseSBOMResolution, false, "Use SBOM resolution instead of legacy CLI.")
	flagSet.Bool(workflow.FlagPrune, false, "When set, controls graph output format. true=pruned JSONL, false=complete JSONL.")
	flagSet.Bool(workflow.FlagPrintEffectiveGraph, false, "Return the pruned dependency graph.")
	flagSet.Bool(workflow.FlagPrintEffectiveGraphWithErrors, false, "Return errors in the pruned dependency graph output.")
	flagSet.Bool(workflow.FlagDotnetRuntimeResolution, false, "Required. You must use this option when you test .NET projects using Runtime Resolution Scanning.")
	flagSet.String(workflow.FlagDotnetTargetFramework, "",
		"Optional. You may use this option if your solution contains multiple <TargetFramework> directives. "+
			"If you do not specify the option --dotnet-target-framework, all supported Target Frameworks will be scanned.")
	flagSet.Bool(workflow.FlagUvWorkspacePackages, false, "Include all uv workspace packages in the dependency graph output")
	flagSet.Bool(workflow.FlagForceSingleGraph, false, "Prevent splitting the dependency graph within an ecosystem.")

	return flagSet
}
