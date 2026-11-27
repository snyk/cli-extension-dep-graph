package workflow

const (
	FlagFailFast                      = "fail-fast"
	FlagAllProjects                   = "all-projects"
	FlagPrintOutputJsonlWithErrors    = "print-output-jsonl-with-errors"
	FlagDev                           = "dev"
	FlagExclude                       = "exclude"
	FlagExcludePaths                  = "exclude-paths"
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
	FlagGradleRefreshDependencies     = "gradle-refresh-dependencies"
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
	FlagIncludeComponentMetadata      = "include-component-metadata"
	FlagUseSBOMResolution             = "use-sbom-resolution"
	FlagPrintEffectiveGraph           = "effective-graph"
	FlagPrintEffectiveGraphWithErrors = "effective-graph-with-errors"
	FlagDotnetRuntimeResolution       = "dotnet-runtime-resolution"
	FlagDotnetTargetFramework         = "dotnet-target-framework"
	// TODO: rename this flag to remove the uv-specific reference.
	FlagUvWorkspacePackages = "internal-uv-workspace-packages"
	FlagForceSingleGraph    = "force-single-graph"
)

// ConfigKeyKeepCallerGraphMode is an internal configuration key, not a CLI flag.
// A caller sets it to have SBOM resolution hand its graph flags to the legacy CLI
// unchanged (legacy.GraphModeCaller) instead of forcing the effective graph with
// errors. cli-extension-sbom sets it so `snyk sbom` gets the same legacy graphs as
// the standard depgraph path; `snyk test` (cli-extension-os-flows) does not.
const ConfigKeyKeepCallerGraphMode = "internal-keep-caller-graph-mode"
