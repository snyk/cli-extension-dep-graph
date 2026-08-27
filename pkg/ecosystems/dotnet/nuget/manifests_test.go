package nuget

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageSet_AddKeepsTheFirstDeclaration(t *testing.T) {
	set := newPackageSet()

	set.add("A", "1.0")
	set.add("B", "1.0")
	set.add("A", "2.0")

	assert.Equal(t, []declaredPackage{{"A", "1.0"}, {"B", "1.0"}}, set.packages)

	// Nothing on this path folds case: snyk-nuget-plugin indexes these by plain
	// object key, so JQUERY and jQuery are two packages.
	set.add("a", "3.0")
	assert.Len(t, set.packages, 3)
}

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

// writeTemp writes one file into a fresh temp directory and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}
