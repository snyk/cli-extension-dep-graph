package nuget

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadPackagesConfig(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		packages []declaredPackage
		hints    []string
	}{
		{
			name: "a plain manifest",
			content: `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="jQuery" version="3.2.1" targetFramework="net461" />
  <package id="Moment.js" version="2.20.1" targetFramework="net452" />
</packages>`,
			packages: []declaredPackage{{"jQuery", "3.2.1"}, {"Moment.js", "2.20.1"}},
			hints:    []string{"net461", "net452"},
		},
		{
			name: "a byte order mark and interleaved comments",
			content: "\xef\xbb\xbf" + `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Antlr" version="3.4.1.9004" targetFramework="net45" />
  <!-- following packages have nuspecs in utf-16 LE encoding -->
  <package id="Swagger.Net" version="0.5.5" targetFramework="net45" />
</packages>`,
			packages: []declaredPackage{{"Antlr", "3.4.1.9004"}, {"Swagger.Net", "0.5.5"}},
			hints:    []string{"net45", "net45"},
		},
		{
			name: "an entry with no targetFramework contributes no hint",
			content: `<packages>
  <package id="jQuery" version="3.2.1" />
</packages>`,
			packages: []declaredPackage{{"jQuery", "3.2.1"}},
		},
		{
			// A restored project with nothing installed. Root-only is the right
			// answer, and it is not the same as a manifest we could not read.
			name:    "an empty packages element",
			content: "\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<packages>\n</packages>",
		},
		{
			// Order is kept as written. Deduplication happens once the packages
			// folder has had its say, so both entries have to survive to there.
			name: "a repeated id keeps both entries in order",
			content: `<packages>
  <package id="jQuery" version="1.9.1" targetFramework="net40" />
  <package id="jQuery" version="3.2.1" targetFramework="net40" />
</packages>`,
			packages: []declaredPackage{{"jQuery", "1.9.1"}, {"jQuery", "3.2.1"}},
			hints:    []string{"net40", "net40"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeTemp(t, packagesConfigFile, test.content)

			manifest, err := readPackagesConfig(path, packagesConfigFile)
			require.NoError(t, err)

			assert.Equal(t, test.packages, manifest.packages)
			assert.Equal(t, test.hints, manifest.frameworkHints)
			assert.Empty(t, manifest.rootName, "packages.config never names its project")
			assert.Empty(t, manifest.rootVersion)
		})
	}
}

func TestReadPackagesConfig_Rejects(t *testing.T) {
	tests := map[string]string{
		// The root check earns its keep here: <package> children are matched by
		// name wherever they sit, so this parses cleanly into two packages and
		// would otherwise be reported as an ordinary project.
		"a configuration root rather than packages": `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <package id="Braintree" version="3.3.0" targetFramework="net452" />
</configuration>`,
		"unclosed elements": `<packages><package id="jQuery" version="3.2.1" />`,
		"not XML at all":    `{"dependencies": {}}`,
		"empty":             "",
	}

	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := writeTemp(t, packagesConfigFile, content)

			_, err := readPackagesConfig(path, packagesConfigFile)
			require.Error(t, err)
			assert.NotEmpty(t, detailOf(t, err), "the user is shown the detail, so it has to say something")
		})
	}
}

func TestReadPackagesConfig_Missing(t *testing.T) {
	_, err := readPackagesConfig(filepath.Join(t.TempDir(), packagesConfigFile), packagesConfigFile)
	require.Error(t, err)
}

func TestReadProjectJSON(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		packages []declaredPackage
	}{
		{
			name:     "top-level dependencies, in document order",
			content:  `{"dependencies": {"Newtonsoft.Json": "8.0.3", "RouteMagic": "1.3"}}`,
			packages: []declaredPackage{{"Newtonsoft.Json", "8.0.3"}, {"RouteMagic", "1.3"}},
		},
		{
			// The point of walking the whole document: per-framework dependency
			// blocks are picked up without this resolver knowing the schema.
			name: "dependencies nested under frameworks",
			content: `{
  "dependencies": {"Top": "1.0"},
  "frameworks": {"net45": {"dependencies": {"Nested": "2.0"}}}
}`,
			packages: []declaredPackage{{"Top", "1.0"}, {"Nested", "2.0"}},
		},
		{
			name:     "an object-valued dependency carries its version",
			content:  `{"dependencies": {"Pinned": {"version": "3.0", "type": "build"}}}`,
			packages: []declaredPackage{{"Pinned", "3.0"}},
		},
		{
			name:     "a dependency with no version at all is still reported",
			content:  `{"dependencies": {"Vague": {"type": "build"}, "Null": null}}`,
			packages: []declaredPackage{{"Vague", unknownVersion}, {"Null", unknownVersion}},
		},
		{
			name:     "a non-string version is reported as written",
			content:  `{"dependencies": {"Numeric": 5, "Fractional": 10.0, "Boolean": true}}`,
			packages: []declaredPackage{{"Numeric", "5"}, {"Fractional", "10.0"}, {"Boolean", "true"}},
		},
		{
			// snyk-nuget-plugin reads `version` as a plain property, so a
			// differently-cased key is not a version. Decoding into a struct
			// would accept it: encoding/json matches field names
			// case-insensitively.
			name:     "the version key is case-sensitive",
			content:  `{"dependencies": {"Shouty": {"VERSION": "1.0"}}}`,
			packages: []declaredPackage{{"Shouty", unknownVersion}},
		},
		{
			// An array has no version to read, the same as null.
			name:     "an array-valued dependency",
			content:  `{"dependencies": {"Listy": ["1.0"]}}`,
			packages: []declaredPackage{{"Listy", unknownVersion}},
		},
		{
			// Arrays are walked too, so a dependency block inside one is found.
			name:     "dependencies inside an array",
			content:  `{"frameworks": {"net45": {"imports": [{"dependencies": {"Deep": "9.0"}}]}}}`,
			packages: []declaredPackage{{"Deep", "9.0"}},
		},
		{
			// Assigning to a JavaScript object twice keeps the first position
			// and the last value, and that is what decides the reported version.
			name: "a name declared twice keeps its position and takes the later version",
			content: `{
  "dependencies": {"Dup": "1.0", "Other": "1.0"},
  "frameworks": {"net45": {"dependencies": {"Dup": "2.0"}}}
}`,
			packages: []declaredPackage{{"Dup", "2.0"}, {"Other", "1.0"}},
		},
		{
			// A package literally called "dependencies" must not be mistaken
			// for another group to descend into.
			name:     "a dependencies object is not descended into",
			content:  `{"dependencies": {"dependencies": "1.0"}}`,
			packages: []declaredPackage{{"dependencies", "1.0"}},
		},
		{
			name:    "a project with no dependencies is not an error",
			content: `{"frameworks": {"net45": {}}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeTemp(t, projectJSONFile, test.content)

			manifest, err := readProjectJSON(path, projectJSONFile)
			require.NoError(t, err)

			assert.Equal(t, test.packages, manifest.packages)
			assert.Empty(t, manifest.frameworkHints,
				"project.json offers no framework fallback, so a .csproj is the only source")
		})
	}
}

func TestReadProjectJSON_ProjectNameAndVersion(t *testing.T) {
	path := writeTemp(t, projectJSONFile,
		`{"dependencies": {"A": "1.0"}, "project": {"version": "4.5.6", "restore": {"projectName": "Chosen"}}}`)

	manifest, err := readProjectJSON(path, projectJSONFile)
	require.NoError(t, err)

	assert.Equal(t, "Chosen", manifest.rootName)
	assert.Equal(t, "4.5.6", manifest.rootVersion)
}

func TestReadProjectJSON_Rejects(t *testing.T) {
	tests := []struct {
		name string
		// notOurs distinguishes a file that belongs to another ecosystem from
		// one that is a broken .NET manifest. It is not cosmetic: it decides
		// whether the file is reported at debug or at error, so an Nx workspace
		// does not read as a few hundred failures.
		notOurs bool
		content string
	}{
		{
			// project.json is a common enough file name that other ecosystems
			// use it — an Nx workspace most notably. Resolving one of those as
			// a .NET project would report nonsense rather than nothing.
			name:    "an Nx project file",
			notOurs: true,
			content: `{"name": "web", "projectType": "application", "targets": {}}`,
		},
		{
			name:    "an unrelated JSON object",
			notOurs: true,
			content: `{"hello": "world"}`,
		},
		{
			name:    "truncated JSON",
			content: `{"dependencies": `,
		},
		{
			name:    "not JSON at all",
			content: `<packages></packages>`,
		},
		{
			name: "empty",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeTemp(t, projectJSONFile, test.content)

			_, err := readProjectJSON(path, projectJSONFile)
			require.Error(t, err)

			if test.notOurs {
				assert.ErrorIs(t, err, errNotDotnetManifest)
				return
			}

			assert.NotErrorIs(t, err, errNotDotnetManifest,
				"a manifest we could not read is a real failure, not someone else's file")
			assert.NotEmpty(t, detailOf(t, err), "the user is shown the detail, so it has to say something")
		})
	}
}

func TestPackageSet(t *testing.T) {
	set := newPackageSet()

	set.add("A", "1.0")
	set.add("B", "1.0")
	set.add("A", "2.0")
	assert.Equal(t, []declaredPackage{{"A", "1.0"}, {"B", "1.0"}}, set.packages,
		"add keeps the first declaration of a name")

	set.replace("B", "3.0")
	set.replace("Absent", "1.0")
	assert.Equal(t, []declaredPackage{{"A", "1.0"}, {"B", "3.0"}}, set.packages,
		"replace never widens the set")

	set.set("A", "4.0")
	set.set("C", "1.0")
	assert.Equal(t, []declaredPackage{{"A", "4.0"}, {"B", "3.0"}, {"C", "1.0"}}, set.packages,
		"set overwrites in place, keeping position")

	pkg, ok := set.get("A")
	require.True(t, ok)
	assert.Equal(t, declaredPackage{"A", "4.0"}, pkg)

	// Nothing on this path folds case: snyk-nuget-plugin indexes these by plain
	// object key, so JQUERY and jQuery are two packages.
	_, ok = set.get("a")
	assert.False(t, ok)
}

// writeTemp writes one file into a fresh temp directory and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

// The search for dependency groups re-decodes the subtree below it at every
// level, so an absurdly nested file would otherwise cost time quadratic in its
// depth — 8000 levels of a 48KB file took four seconds before the bound.
// Nothing that deep is a .NET project.json.
func TestReadProjectJSON_BoundsHowDeepItLooks(t *testing.T) {
	nest := func(depth int) string {
		body := `{"dependencies": {"Leaf": "1.0"}}`
		for range depth {
			body = `{"a":` + body + `}`
		}

		return `{"frameworks": {"net45": ` + body + `}}`
	}

	within := writeTemp(t, projectJSONFile, nest(maxProjectJSONDepth-4))

	manifest, err := readProjectJSON(within, projectJSONFile)
	require.NoError(t, err)
	assert.Equal(t, []declaredPackage{{"Leaf", "1.0"}}, manifest.packages)

	beyond := writeTemp(t, projectJSONFile, nest(maxProjectJSONDepth+10))

	start := time.Now()
	manifest, err = readProjectJSON(beyond, projectJSONFile)
	require.NoError(t, err, "an over-nested file is still a readable file, just not a .NET one")
	assert.Empty(t, manifest.packages, "the walk stops rather than grinding through it")
	assert.Less(t, time.Since(start), 2*time.Second)
}
