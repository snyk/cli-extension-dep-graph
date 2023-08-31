package depgraph

import "github.com/spf13/pflag"

const (
	FlagFailFast                     = "fail-fast"
	FlagAllProjects                  = "all-projects"
	FlagDev                          = "dev"
	FlagFile                         = "file"
	FlagDetectionDepth               = "detection-depth"
	FlagPruneRepeatedSubdependencies = "prune-repeated-subdependencies"
	FlagMavenAggregateProject        = "maven-aggregate-project"
	FlagScanUnmanaged                = "scan-unmanaged"
	FlagScanAllUnmanaged             = "scan-all-unmanaged"
	FlagSubProject                   = "sub-project"
	FlagGradleSubProject             = "gradle-sub-project"
	FlagAllSubProjects               = "all-sub-projects"
	FlagConfigurationMatching        = "configuration-matching"
	FlagConfigurationAttributes      = "configuration-attributes"
	FlagInitScript                   = "init-script"
)

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("depgraph", pflag.ExitOnError)

	flagSet.Bool(FlagFailFast, false, "Fail fast when scanning all projects")
	flagSet.Bool(FlagAllProjects, false, "Enable all projects")
	flagSet.Bool(FlagDev, false, "Include dev dependencies")
	flagSet.String(FlagFile, "", "Input file")
	flagSet.String(FlagDetectionDepth, "", "Detection depth")
	flagSet.BoolP(FlagPruneRepeatedSubdependencies, "p", false, "Prune repeated sub-dependencies")
	flagSet.Bool(FlagMavenAggregateProject, false, "Ensure all modules are resolvable by the Maven reactor.")
	flagSet.Bool(FlagScanUnmanaged, false, "Specify an individual JAR, WAR, or AAR file.")
	flagSet.Bool(FlagScanAllUnmanaged, false, "Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder.")
	flagSet.String(FlagSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.String(FlagGradleSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.Bool(FlagAllSubProjects, false, "Test all sub-projects in a multi-project build.")
	flagSet.String(FlagConfigurationMatching, "", "Resolve dependencies using only configuration(s) that match the specified Java regular expression.")
	flagSet.String(FlagConfigurationAttributes, "", "Select certain values of configuration attributes to install and resolve dependencies.")
	flagSet.String(FlagInitScript, "", "Use for projects that contain a Gradle initialization script.")

	return flagSet
}
