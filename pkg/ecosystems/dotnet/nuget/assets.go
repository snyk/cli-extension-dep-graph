package nuget

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// projectAssets is the subset of project.assets.json this resolver reads,
// mirroring snyk-nuget-plugin's v3 parser
// (lib/nuget-parser/parsers/dotnet-core-v3-parser.ts). `libraries` and
// `packageFolders` are declared upstream but never read, so they are omitted.
type projectAssets struct {
	// Targets maps a target framework moniker to its resolved package set, keyed
	// by "<name>/<version>": the authoritative source of versions and edges.
	//
	// Both levels preserve document order — the outer because matchTargetsKey
	// falls back to position, the inner because two keys differing only in case
	// collapse to one package and the winner must not vary between runs.
	Targets orderedMap[orderedMap[assetsTargetEntry]]

	// ProjectFileDependencyGroups maps a target framework to the project's
	// direct dependencies as constraint strings, e.g. "Newtonsoft.Json >= 13.0.3".
	ProjectFileDependencyGroups map[string][]string

	Project assetsProject

	// projectPresent records whether the `project` field existed at all, so a
	// missing one is reported differently from one that is merely empty.
	projectPresent bool
}

// assetsTargetEntry is one resolved package within a target framework.
//
// Dependencies holds minimum constraints, not resolved versions (see
// resolvePackages), and its order decides sibling walk order, which decides
// which edges get pruned. `type` is absent because upstream never inspects it:
// a `type: "project"` entry becomes an ordinary node.
type assetsTargetEntry struct {
	Dependencies orderedMap[string] `json:"dependencies"`
}

// project.restore is absent until --assets-project-name is honored (CMPA-718).
// Upstream reads restore.projectName there; decoding it before the flag exists
// would only suggest it is already supported.
type assetsProject struct {
	Version    string                             `json:"version"`
	Frameworks orderedMap[assetsProjectFramework] `json:"frameworks"`
}

type assetsProjectFramework struct {
	// TargetAlias is the short, user-facing moniker (e.g. "net7.0-windows")
	// where the framework key itself is a longer one ("net7.0-windows7.0"). It
	// is not always present.
	TargetAlias string `json:"targetAlias"`
}

// UnmarshalJSON decodes the assets file, recording whether `project` was present
// at all — encoding/json cannot otherwise tell an absent object from an empty
// one.
func (a *projectAssets) UnmarshalJSON(data []byte) error {
	var raw struct {
		Targets                     orderedMap[orderedMap[assetsTargetEntry]] `json:"targets"`
		ProjectFileDependencyGroups map[string][]string                       `json:"projectFileDependencyGroups"`
		Project                     json.RawMessage                           `json:"project"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("decoding project assets: %w", err)
	}

	a.Targets = raw.Targets
	a.ProjectFileDependencyGroups = raw.ProjectFileDependencyGroups
	a.projectPresent = len(raw.Project) > 0 && string(raw.Project) != "null"

	if a.projectPresent {
		if err := json.Unmarshal(raw.Project, &a.Project); err != nil {
			return fmt.Errorf("decoding the project section of project assets: %w", err)
		}
	}

	return nil
}

// readProjectAssets loads, parses and validates a project.assets.json.
//
// path is read; displayPath is what messages name, since discovery hands out
// absolute paths and quoting one leaks the build agent's layout.
//
// Errors come from the error catalog: the dep-graph workflow only shows the user
// a message when snyk_errors.Error.Detail is set.
func readProjectAssets(path, displayPath string) (*projectAssets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Telling someone to re-run `dotnet restore` when the file is present but
		// unreadable sends them the wrong way.
		if errors.Is(err, fs.ErrNotExist) {
			return nil, snykecosystems.NewUnprocessableFileError(
				fmt.Sprintf("Could not find %s. Run `dotnet restore` on the project so the file is created.", displayPath),
				snyk_errors.WithCause(err),
			)
		}

		return nil, snykecosystems.NewUnprocessableFileError(
			fmt.Sprintf("Could not read %s: %v. The file is present but could not be opened, "+
				"which is a filesystem problem rather than a problem with the project.", displayPath, readFailureReason(err)),
			snyk_errors.WithCause(err),
		)
	}

	var assets projectAssets
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil, snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("Could not parse %s as JSON. The restore that produced it may not have completed.", displayPath),
			snyk_errors.WithCause(err),
		)
	}

	if err := assets.validate(displayPath); err != nil {
		return nil, err
	}

	return &assets, nil
}

// readFailureReason reduces a read error to its cause. os.ReadFile returns a
// *fs.PathError whose Error() embeds the absolute path, which would leak the
// build agent's layout.
func readFailureReason(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}

	return err
}

// validate rejects assets files that cannot produce a graph, mirroring
// validateManifest in snyk-nuget-plugin's v3 parser.
//
// projectFileDependencyGroups may be absent — a project with no direct
// dependencies is legitimate — and project.version is not required.
func (a *projectAssets) validate(path string) error {
	switch {
	case !a.projectPresent:
		return snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("No project section was found in %s.", path),
		)
	case a.Project.Frameworks.Len() == 0:
		return snykecosystems.NewNoTargetFrameworksFoundError(
			fmt.Sprintf("No target frameworks were found in %s.", path),
		)
	case a.Targets.Len() == 0:
		return snykecosystems.NewUnparseableManifestError(
			fmt.Sprintf("No targets were found in %s. The restore that produced it may not have completed.", path),
		)
	}

	// The moniker becomes the project's target runtime, which is part of its
	// identity, so a nameless framework is refused rather than carried.
	for _, framework := range a.targetFrameworks() {
		if framework == "" {
			return snykecosystems.NewNoTargetFrameworksFoundError(
				fmt.Sprintf("A target framework in %s has no name.", path),
			)
		}
	}

	return nil
}

// targetFrameworks lists the project's frameworks in document order, preferring
// each entry's targetAlias over its key. The alias is the moniker users
// recognize, and is what gets reported as the target runtime.
func (a *projectAssets) targetFrameworks() []string {
	frameworks := make([]string, 0, a.Project.Frameworks.Len())

	for _, key := range a.Project.Frameworks.Keys() {
		framework, _ := a.Project.Frameworks.Get(key)
		if framework.TargetAlias != "" {
			frameworks = append(frameworks, framework.TargetAlias)
			continue
		}

		frameworks = append(frameworks, key)
	}

	return frameworks
}

// assetsFrameworkName converts a target framework to the form used as a
// `targets` key, for the three families where the sections disagree: `targets`
// uses long monikers before net5.0 (".NETCoreApp,Version=v3.1") where
// project.frameworks uses the short one.
//
// snyk-nuget-plugin reads these from the SDK and only handles netstandard. The
// mappings are mechanical, so derive all three — otherwise a pre-net5 framework
// in a multi-target project cannot be attributed. net5.0 and later, and anything
// unrecognized, are returned unchanged.
func assetsFrameworkName(framework string) string {
	if version, ok := shortFrameworkVersion(framework, netstandardPrefix); ok {
		return ".NETStandard,Version=v" + version
	}

	if version, ok := shortFrameworkVersion(framework, netcoreappPrefix); ok {
		return ".NETCoreApp,Version=v" + version
	}

	if version, ok := netFrameworkVersion(framework); ok {
		return ".NETFramework,Version=v" + version
	}

	return framework
}

// shortFrameworkVersion returns the dotted version following prefix. The
// remainder must start with a digit, or "netstandardapp1.5" — a real moniker —
// becomes ".NETStandard,Version=vapp1.5", which exists nowhere.
func shortFrameworkVersion(framework, prefix string) (string, bool) {
	version, ok := strings.CutPrefix(framework, prefix)
	if !ok || version == "" || !isDigit(version[0]) {
		return "", false
	}

	return version, true
}

// netFrameworkVersion expands a .NET Framework moniker's compact version, each
// digit its own component: net48 is v4.8, net472 is v4.7.2. Only an all-digit
// remainder qualifies, so net5.0 and later are left alone. A bare "net4" is
// v4.0 (NuGet/Home#1371).
func netFrameworkVersion(framework string) (string, bool) {
	digits, ok := strings.CutPrefix(framework, netPrefix)
	if !ok || digits == "" || len(digits) > maxNetFrameworkDigits {
		return "", false
	}

	for i := range len(digits) {
		if !isDigit(digits[i]) {
			return "", false
		}
	}

	if len(digits) == 1 {
		return digits + ".0", true
	}

	components := make([]string, 0, len(digits))
	for i := range len(digits) {
		components = append(components, digits[i:i+1])
	}

	return strings.Join(components, "."), true
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// matchTargetsKey finds the `targets` key describing the given framework.
// Platform versions drift in both directions ("net8.0-windows" against
// "net8.0-windows7.0"), so a match in either direction is accepted.
//
// Two departures from upstream, both stopping one framework being resolved
// against another's packages:
//
//   - Longest match wins, not first in document order. For net8.0;net8.0-windows
//     the keys are "net8.0" and "net8.0-windows7.0"; taking the first hands the
//     Windows framework the non-Windows package set.
//   - The positional fallback applies only to a single-target project. Upstream
//     falls back unconditionally, so netcoreapp3.1;net472 reports the netcoreapp
//     packages twice and drops net472's.
//
// Returns "" when no key can be attributed; the caller reports the failure
// rather than guessing.
func (a *projectAssets) matchTargetsKey(framework string) string {
	// Both spellings stay in play: a mapping that does not apply to this project
	// must not rule out the name the project declared.
	names := []string{framework}
	if remapped := assetsFrameworkName(framework); remapped != framework {
		names = append(names, remapped)
	}

	for _, name := range names {
		if _, ok := a.Targets.Get(name); ok {
			return name
		}
	}

	keys := a.Targets.Keys()

	longest := ""

	for _, key := range keys {
		if !anyPrefixMatch(key, names) {
			continue
		}

		if len(key) > len(longest) {
			longest = key
		}
	}

	if longest != "" {
		return longest
	}

	if len(keys) == 1 {
		return keys[0]
	}

	return ""
}

// anyPrefixMatch reports whether key and any of names are a prefix of each
// other, in either direction.
func anyPrefixMatch(key string, names []string) bool {
	for _, name := range names {
		if strings.HasPrefix(key, name) || strings.HasPrefix(name, key) {
			return true
		}
	}

	return false
}

// directDependencies extracts the direct dependency names for a framework from
// projectFileDependencyGroups. Entries look like "Newtonsoft.Json >= 13.0.3";
// the constraint is ignored, since the resolved version comes from `targets`.
//
// Upstream indexes this map unguarded and throws when the key is missing, taking
// down the scan. Degrade instead: use the sole group where there is one, and
// otherwise report no direct dependencies.
func (a *projectAssets) directDependencies(targetsKey string) []string {
	entries, ok := a.ProjectFileDependencyGroups[targetsKey]
	if !ok {
		entries, ok = a.soleDependencyGroup()
		if !ok {
			return nil
		}
	}

	names := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}

		// Upstream keys these by name, so a repeated entry collapses. Keeping both
		// would walk the package twice and hang a pruned leaf off the root.
		name := fields[0]
		if _, duplicate := seen[name]; duplicate {
			continue
		}

		seen[name] = struct{}{}
		names = append(names, name)
	}

	return names
}

// soleDependencyGroup returns the only dependency group, when there is exactly
// one. Go cannot index a map, so reading the single value still needs a loop.
func (a *projectAssets) soleDependencyGroup() ([]string, bool) {
	if len(a.ProjectFileDependencyGroups) != 1 {
		return nil, false
	}

	for _, only := range a.ProjectFileDependencyGroups {
		return only, true
	}

	return nil, false
}

// resolvedPackage is one entry from a target framework's package set, with the
// casing and version the assets file considers authoritative.
type resolvedPackage struct {
	name    string
	version string
	deps    orderedMap[string]
}

// resolvePackages indexes a target framework's packages by lowercased name.
// NuGet names are case-insensitive and the assets file is inconsistent between
// its own sections; the casing on the `targets` key is the one to report.
//
// The version comes from the `targets` key too, never from a parent's
// dependencies map — that is only a minimum constraint, and reading it would
// miss transitive pinning and central package management.
//
// Where two keys differ only in case the later one wins, so iteration follows
// document order: a plain Go map would pick differently between runs.
func resolvePackages(target *orderedMap[assetsTargetEntry]) map[string]resolvedPackage {
	resolved := make(map[string]resolvedPackage, target.Len())

	for _, key := range target.Keys() {
		entry, _ := target.Get(key)

		name, rest, found := strings.Cut(key, "/")
		if !found {
			// A target key without a version is not something the format
			// produces; skip rather than emit a versionless package.
			continue
		}

		// Anything past the version is dropped, matching upstream's
		// `const [name, version] = key.split('/')` destructuring.
		version, _, _ := strings.Cut(rest, "/")

		resolved[strings.ToLower(name)] = resolvedPackage{
			name:    name,
			version: version,
			deps:    entry.Dependencies,
		}
	}

	return resolved
}

// isFilteredPackage reports whether a package should be left out of the graph.
// `runtime` and `runtime.native.*` describe platform-specific assets rather than
// dependencies a user can act on (dotnet/core#7568); upstream filters the same
// prefix, case-sensitively, against the declared name.
func isFilteredPackage(name string) bool {
	return strings.HasPrefix(name, filteredPackagePrefix)
}
