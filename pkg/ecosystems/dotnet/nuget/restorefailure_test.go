package nuget

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// A restore that resolved some of a project's packages and not others leaves a
// graph short of a dependency, and nothing downstream looks at a dependency
// that is not in the graph. The diagnostic naming the absent package is what
// gives it away, since something did resolve.
func TestBuildDepGraph_PartlyResolvedFrameworkReportsTheRestoreFailure(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": { "net8.0": { "Newtonsoft.Json/13.0.3": {} } },
      "projectFileDependencyGroups": {
        "net8.0": [ "Newtonsoft.Json >= 13.0.3", "Totally.Nonexistent >= 9.9.9" ]
      },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } },
      "logs": [
        {
          "code": "NU1101",
          "level": "Error",
          "message": "Unable to find package Totally.Nonexistent.",
          "libraryId": "Totally.Nonexistent",
          "targetGraphs": [ "net8.0" ]
        }
      ]
    }`)

	_, err := buildDepGraph(t.Context(), assets, "RootProject", "net8.0")

	require.Error(t, err, "a graph missing a declared dependency must not pass as resolved")
	assert.Contains(t, detailOf(t, err), "NU1101")
	assert.Contains(t, detailOf(t, err), "Unable to find package Totally.Nonexistent.")
}

// A package the framework cannot use is still recorded under it, but with none
// of its own dependencies, so everything below it silently disappears. The
// package being present says nothing about the closure being complete, which is
// why any failure on a framework disqualifies its graph.
//
// Here ModernOnly resolves under both frameworks and brings Newtonsoft.Json
// with it under net8.0 only; on net472 it arrives childless.
func TestBuildDepGraph_FailedFrameworkIsReportedEvenWhereThePackageResolved(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": {
        "net8.0": {
          "ModernOnly/1.0.0": { "dependencies": { "Newtonsoft.Json": "13.0.3" } },
          "Newtonsoft.Json/13.0.3": {}
        },
        ".NETFramework,Version=v4.7.2": { "ModernOnly/1.0.0": {} }
      },
      "projectFileDependencyGroups": {
        "net8.0": [ "ModernOnly >= 1.0.0" ],
        ".NETFramework,Version=v4.7.2": [ "ModernOnly >= 1.0.0" ]
      },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {}, "net472": {} } },
      "logs": [
        {
          "code": "NU1202",
          "level": "Error",
          "message": "Package ModernOnly 1.0.0 is not compatible with net472.",
          "libraryId": "ModernOnly",
          "targetGraphs": [ ".NETFramework,Version=v4.7.2" ]
        }
      ]
    }`)

	_, err := buildDepGraph(t.Context(), assets, "RootProject", ".NETFramework,Version=v4.7.2")
	require.Error(t, err, "the package is present but arrives with none of its dependencies")
	assert.Contains(t, detailOf(t, err), "NU1202")

	// The framework the failure does not name keeps the closure it resolved.
	graph, err := buildDepGraph(t.Context(), assets, "RootProject", "net8.0")
	require.NoError(t, err)
	assert.Contains(t, pkgIDs(graph.Pkgs), "Newtonsoft.Json@13.0.3",
		"the transitive dependency the failing framework lost")
}

// A multi-targeting project can fail on one framework and resolve on another.
// The frameworks a diagnostic names are `targets` keys, which is what
// matchTargetsKey hands back, so each framework is judged on its own.
func TestBuildDepGraph_FailureIsScopedToTheFrameworksItNames(t *testing.T) {
	const content = `{
      "targets": {
        "net8.0": { "Newtonsoft.Json/13.0.3": {} },
        ".NETFramework,Version=v4.7.2": { "Newtonsoft.Json/13.0.3": {} }
      },
      "projectFileDependencyGroups": {
        "net8.0": [ "Newtonsoft.Json >= 13.0.3" ],
        ".NETFramework,Version=v4.7.2": [ "Newtonsoft.Json >= 13.0.3", "Modern.Only >= 1.0.0" ]
      },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {}, "net472": {} } },
      "logs": [
        {
          "code": "NU1202",
          "level": "Error",
          "message": "Package Modern.Only 1.0.0 is not compatible with net472.",
          "libraryId": "Modern.Only",
          "targetGraphs": [ ".NETFramework,Version=v4.7.2" ]
        }
      ]
    }`

	graph, err := buildDepGraph(t.Context(), assetsFrom(t, content), "RootProject", "net8.0")
	require.NoError(t, err, "the framework the diagnostic does not name is unaffected")
	assert.Contains(t, pkgIDs(graph.Pkgs), "Newtonsoft.Json@13.0.3")

	_, err = buildDepGraph(t.Context(), assetsFrom(t, content), "RootProject", ".NETFramework,Version=v4.7.2")
	require.Error(t, err, "the framework it names lost a declared dependency")
	assert.Contains(t, detailOf(t, err), "NU1202")
}

// A diagnostic naming no framework applies to the project as a whole.
func TestBuildDepGraph_FailureNamingNoFrameworkAppliesToAll(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": { "net8.0": {} },
      "projectFileDependencyGroups": { "net8.0": [ null ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } },
      "logs": [
        {
          "code": "NU1010",
          "level": "Error",
          "message": "The PackageReference items do not specify a version."
        }
      ]
    }`)

	_, err := buildDepGraph(t.Context(), assets, "RootProject", "net8.0")

	require.Error(t, err, "a project-wide failure covers every framework")
	assert.Contains(t, detailOf(t, err), "NU1010")
}

// A warning did not fail the restore, so it must not fail the project.
func TestBuildDepGraph_WarningsAreNotFailures(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": { "net8.0": { "OldOnly/1.0.0": {} } },
      "projectFileDependencyGroups": { "net8.0": [ "OldOnly >= 1.0.0" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } },
      "logs": [
        {
          "code": "NU1701",
          "level": "Warning",
          "message": "Package OldOnly 1.0.0 was restored using .NETFramework instead of net8.0.",
          "libraryId": "OldOnly",
          "targetGraphs": [ "net8.0" ]
        }
      ]
    }`)

	graph, err := buildDepGraph(t.Context(), assets, "RootProject", "net8.0")

	require.NoError(t, err)
	assert.Contains(t, pkgIDs(graph.Pkgs), "OldOnly@1.0.0")
}

// An assets file carrying no diagnostics at all — an SDK old enough not to
// write them, or a restore that recorded nothing — reads exactly as it did
// before they were decoded, so the graph still speaks for itself.
func TestBuildDepGraph_NoLogsLeavesTheGraphToSpeakForItself(t *testing.T) {
	assets := assetsFrom(t, `{
      "targets": { "net8.0": { "Newtonsoft.Json/13.0.3": {} } },
      "projectFileDependencyGroups": { "net8.0": [ "Newtonsoft.Json >= 13.0.3" ] },
      "project": { "version": "1.0.0", "frameworks": { "net8.0": {} } }
    }`)

	graph, err := buildDepGraph(t.Context(), assets, "RootProject", "net8.0")

	require.NoError(t, err)
	assert.Contains(t, pkgIDs(graph.Pkgs), "Newtonsoft.Json@13.0.3")
}

// The code decides which catalog entry explains the failure, so a user can tell
// a project they can fix from one they cannot. Every code carries its message
// through, including one with no dedicated entry.
func TestCatalogErrorForCode(t *testing.T) {
	for code, wantCode := range map[string]string{
		"NU1008": "SNYK-OS-DOTNET-0012",
		"NU1010": "SNYK-OS-DOTNET-0013",
		"NU1015": "SNYK-OS-DOTNET-0014",
		"NU1202": "SNYK-OS-DOTNET-0015",
		"NU1101": "SNYK-OS-DOTNET-0011",
		"NU1301": "SNYK-OS-DOTNET-0011",
	} {
		t.Run(code, func(t *testing.T) {
			err := catalogErrorForCode(code, code+": something went wrong")

			var snykErr snyk_errors.Error
			require.ErrorAs(t, err, &snykErr, "a failure reaching the user must come from the error catalog")
			assert.Equal(t, wantCode, snykErr.ErrorCode)
			assert.Contains(t, snykErr.Detail, code+": something went wrong")
		})
	}
}
