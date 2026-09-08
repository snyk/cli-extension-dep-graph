package nuget

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// targetFramework is a .NET target framework moniker decomposed the way
// snyk-nuget-plugin's toReadableFramework decomposes it
// (lib/nuget-parser/framework.ts).
//
// packages.config and project.json projects carry no resolved dependency set,
// so unlike project.assets.json there is nothing in the manifest that names the
// framework a package was resolved for. One has to be determined all the same:
// it selects which dependency groups of a .nuspec apply, and it is what the
// result reports as its target runtime.
type targetFramework struct {
	// name is the long form: ".NETFramework", ".NETCore" or ".NETStandard".
	// It is compared against .nuspec dependency group monikers.
	name string
	// version is whatever followed the prefix, undotted or not: "45", "4.6.1".
	version string
	// original is the moniker as written, and is what the result reports as its
	// target runtime — "net45", "v4.6.1", "netcoreapp2.0".
	original string
}

// frameworkPrefixes maps a moniker prefix to its long framework name, in the
// order upstream's typeMapping declares them. `net` is tried before
// `netcoreapp` and `netstandard`, which is safe only because the pattern
// requires a digit straight after the prefix.
var frameworkPrefixes = []struct {
	prefix  string
	name    string
	pattern *regexp.Regexp
}{
	{"net", ".NETFramework", frameworkPattern("net")},
	{"netcoreapp", ".NETCore", frameworkPattern("netcoreapp")},
	{"netstandard", ".NETStandard", frameworkPattern("netstandard")},
	{"v", ".NETFramework", frameworkPattern("v")},
}

// frameworkPattern builds upstream's `<prefix>\d.?\d(.?\d)?$`. It is anchored
// only at the end, as upstream's is, and it rejects anything with a trailing
// platform suffix: `net8.0-windows` does not match, and never reaches this path
// anyway because platform-specific monikers only appear in SDK-style projects.
func frameworkPattern(prefix string) *regexp.Regexp {
	return regexp.MustCompile(prefix + `\d.?\d(.?\d)?$`)
}

// toReadableFramework decomposes a moniker, reporting false for one it does not
// recognize. Ported from snyk-nuget-plugin so that an unrecognized moniker
// leaves a project unresolved here exactly as it does today.
func toReadableFramework(moniker string) (targetFramework, bool) {
	// net4 has no second digit to match on. NuGet allows it by design:
	// https://github.com/NuGet/Home/issues/1371
	if moniker == "net4" {
		return targetFramework{name: ".NETFramework", version: "4", original: moniker}, true
	}

	for _, candidate := range frameworkPrefixes {
		if !candidate.pattern.MatchString(moniker) {
			continue
		}

		parts := strings.SplitN(moniker, candidate.prefix, 2)
		if len(parts) < 2 {
			continue
		}

		return targetFramework{name: candidate.name, version: parts[1], original: moniker}, true
	}

	return targetFramework{}, false
}

// csprojTargetFramework reads the target framework out of the first .csproj in
// dir, reporting false when there is no .csproj or none of its property groups
// name a framework this resolver recognizes.
//
// Only .csproj is read — never .vbproj or .fsproj, which are equally valid
// project files. That is snyk-nuget-plugin's behavior (csproj-parser.ts
// filters on /.*\.csproj$/) and widening it here would resolve projects that
// are unresolvable today.
func csprojTargetFramework(dir string) (targetFramework, bool, error) {
	path, ok, err := firstCsproj(dir)
	if err != nil || !ok {
		return targetFramework{}, false, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return targetFramework{}, false, snykecosystems.NewUnprocessableFileError(
			fmt.Sprintf("Could not read %s: %v.", filepath.Base(path), readFailureReason(err)),
			snyk_errors.WithCause(err),
		)
	}

	var project struct {
		PropertyGroups []struct {
			TargetFrameworkVersion []string `xml:"TargetFrameworkVersion"`
			TargetFramework        []string `xml:"TargetFramework"`
			TargetFrameworks       []string `xml:"TargetFrameworks"`
		} `xml:"PropertyGroup"`
	}

	if err := decodeXML(data, &project); err != nil {
		return targetFramework{}, false, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Could not parse %s as XML.", filepath.Base(path)),
			snyk_errors.WithCause(err),
		)
	}

	for _, group := range project.PropertyGroups {
		// One source per property group, in upstream's precedence order. A
		// group naming none of them contributes nothing rather than ending the
		// search: real projects put TargetFramework in a later group than, say,
		// AssemblyName.
		source := firstNonEmpty(group.TargetFrameworkVersion, group.TargetFramework, group.TargetFrameworks)

		for _, moniker := range strings.Split(source, ";") {
			moniker = strings.TrimSpace(moniker)
			if moniker == "" {
				continue
			}

			if framework, ok := toReadableFramework(moniker); ok {
				return framework, true, nil
			}
		}
	}

	return targetFramework{}, false, nil
}

// firstCsproj returns the first .csproj in dir by name. Go sorts directory
// entries, so which one wins is stable across runs — Node's readdirSync leaves
// that to the filesystem.
func firstCsproj(dir string) (path string, found bool, err error) {
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		return "", false, fmt.Errorf("reading directory %s: %w", dir, readErr)
	}

	for _, entry := range entries {
		// Case-sensitively, as snyk-nuget-plugin's /.*\.csproj$/ is: matching
		// App.CSPROJ here would resolve a project the CLI cannot.
		if entry.IsDir() || filepath.Ext(entry.Name()) != csprojExt {
			continue
		}

		return filepath.Join(dir, entry.Name()), true, nil
	}

	return "", false, nil
}

// firstNonEmpty returns the first element of the first non-empty list, which is
// how upstream reads one target framework source per property group.
func firstNonEmpty(sources ...[]string) string {
	for _, source := range sources {
		if len(source) > 0 && source[0] != "" {
			return source[0]
		}
	}

	return ""
}

// minimumTargetFramework picks the lowest moniker declared across a
// packages.config's entries, which is what snyk-nuget-plugin falls back to when
// a project has no .csproj to read.
//
// "Lowest" is a plain string comparison, as upstream's reduce is — so net461
// and net452 yield net452. A minimum this resolver does not recognize leaves
// the project unresolved rather than falling through to the next candidate.
func minimumTargetFramework(monikers []string) (targetFramework, bool) {
	minimum := ""

	for _, moniker := range monikers {
		if moniker == "" {
			continue
		}

		if minimum == "" || moniker < minimum {
			minimum = moniker
		}
	}

	if minimum == "" {
		return targetFramework{}, false
	}

	return toReadableFramework(minimum)
}

// detectTargetFramework decides which framework a packages.config or
// project.json project targets, reporting false when nothing names one.
//
// The .csproj beside the manifest is authoritative — it is where the project
// actually declares its framework. A packages.config falls back to the
// targetFramework attributes NuGet writes onto its own entries; project.json
// gets no fallback, which is upstream's behavior and the reason a project.json
// with no .csproj alongside it cannot be resolved.
func detectTargetFramework(dir string, manifest *frameworkManifest) (targetFramework, bool, error) {
	framework, ok, err := csprojTargetFramework(dir)
	if err != nil {
		return targetFramework{}, false, err
	}
	if ok {
		return framework, true, nil
	}

	framework, ok = minimumTargetFramework(manifest.frameworkHints)

	return framework, ok, nil
}
