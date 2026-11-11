package nuget

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// scanRootName names the directory each case scans. The legacy CLI names every
// project after it, so it is fixed rather than a random temp dir name.
const scanRootName = "scan-root"

// reportedAs is what a project is identified by: the target file it is
// reported under and its root name. A change to either creates a new project
// beside the one already monitored.
type reportedAs struct {
	file, name string
}

// The CLI column is what snyk CLI 1.1305.1 (snyk-nuget-plugin 4.2.0) reports for
// the same layout with SNYK_FORCE_LEGACY_CLI=1, in both its classic and
// --dotnet-runtime-resolution modes. Its getRootName is unchanged through 4.5.8.
// The SCM column is the identity SCM imports depend on.
func TestPlugin_ProjectIdentity(t *testing.T) {
	namedProjectJSON := `{"dependencies": {"Newtonsoft.Json": "8.0.3"},
      "project": { "restore": { "projectName": "FromProjectJSON" } }}`

	tests := []struct {
		name    string
		files   map[string]string
		scanDir string
		options func() *ecosystems.SCAPluginOptions
		cli     []reportedAs
		scm     []reportedAs
	}{
		{
			name:    "SDK-style project under the scanned root",
			files:   map[string]string{"services/cart/Cart.csproj": csprojNet45, "services/cart/obj/project.assets.json": multiTargetAssets},
			options: allProjects,
			cli: []reportedAs{
				{"services/cart/obj/project.assets.json", scanRootName},
				{"services/cart/obj/project.assets.json", scanRootName},
			},
			scm: []reportedAs{
				{"services/cart/Cart.csproj", "cart"},
				{"services/cart/Cart.csproj", "cart"},
			},
		},
		{
			name:    "SDK-style project that is the scanned root",
			files:   map[string]string{"Cart.csproj": csprojNet45, "obj/project.assets.json": multiTargetAssets},
			options: ecosystems.NewPluginOptions,
			cli: []reportedAs{
				{"obj/project.assets.json", scanRootName},
				{"obj/project.assets.json", scanRootName},
			},
			scm: []reportedAs{
				{"Cart.csproj", scanRootName},
				{"Cart.csproj", scanRootName},
			},
		},
		{
			name:    "SDK-style project named by --file",
			files:   map[string]string{"services/cart/Cart.csproj": csprojNet45, "services/cart/obj/project.assets.json": multiTargetAssets},
			options: targetFile("services/cart/obj/project.assets.json"),
			cli: []reportedAs{
				{"services/cart/obj/project.assets.json", scanRootName},
				{"services/cart/obj/project.assets.json", scanRootName},
			},
			scm: []reportedAs{
				{"services/cart/Cart.csproj", "cart"},
				{"services/cart/Cart.csproj", "cart"},
			},
		},
		{
			name:    "SDK-style project scanned from its own directory",
			files:   map[string]string{"services/cart/Cart.csproj": csprojNet45, "services/cart/obj/project.assets.json": multiTargetAssets},
			scanDir: "services/cart",
			options: ecosystems.NewPluginOptions,
			cli: []reportedAs{
				{"obj/project.assets.json", "cart"},
				{"obj/project.assets.json", "cart"},
			},
			scm: []reportedAs{
				{"Cart.csproj", "cart"},
				{"Cart.csproj", "cart"},
			},
		},
		{
			name:    "--assets-project-name with a name recorded by the restore",
			files:   map[string]string{"services/cart/Cart.csproj": csprojNet45, "services/cart/obj/project.assets.json": singleTargetAssets},
			options: func() *ecosystems.SCAPluginOptions { return allProjects().WithAssetsProjectName(true) },
			cli:     []reportedAs{{"services/cart/obj/project.assets.json", "FromAssetsFile"}},
			scm:     []reportedAs{{"services/cart/Cart.csproj", "FromAssetsFile"}},
		},
		{
			name:    "--assets-project-name with no name recorded",
			files:   map[string]string{"services/cart/Cart.csproj": csprojNet45, "services/cart/obj/project.assets.json": multiTargetAssets},
			options: func() *ecosystems.SCAPluginOptions { return allProjects().WithAssetsProjectName(true) },
			cli: []reportedAs{
				{"services/cart/obj/project.assets.json", scanRootName},
				{"services/cart/obj/project.assets.json", scanRootName},
			},
			scm: []reportedAs{
				{"services/cart/Cart.csproj", "cart"},
				{"services/cart/Cart.csproj", "cart"},
			},
		},
		{
			name:    "assets file with no project file beside it",
			files:   map[string]string{"services/orphan/obj/project.assets.json": singleTargetAssets},
			options: allProjects,
			cli:     []reportedAs{{"services/orphan/obj/project.assets.json", scanRootName}},
			scm:     []reportedAs{{"services/orphan/obj/project.assets.json", "orphan"}},
		},
		{
			name:    "packages.config beside a .csproj",
			files:   map[string]string{"services/web/packages.config": packagesConfigManifest, "services/web/Web.csproj": csprojNet45},
			options: allProjects,
			cli:     []reportedAs{{"services/web/packages.config", scanRootName}},
			scm:     []reportedAs{{"services/web/Web.csproj", "web"}},
		},
		{
			name:    "packages.config beside a .vbproj",
			files:   map[string]string{"services/web/packages.config": packagesConfigManifest, "services/web/Web.vbproj": ""},
			options: allProjects,
			cli:     []reportedAs{{"services/web/packages.config", scanRootName}},
			scm:     []reportedAs{{"services/web/Web.vbproj", "web"}},
		},
		{
			name:    "packages.config named by --file",
			files:   map[string]string{"services/web/packages.config": packagesConfigManifest, "services/web/Web.csproj": csprojNet45},
			options: targetFile("services/web/packages.config"),
			cli:     []reportedAs{{"services/web/packages.config", scanRootName}},
			scm:     []reportedAs{{"services/web/Web.csproj", "web"}},
		},
		{
			name:    "packages.config with no project file",
			files:   map[string]string{"services/flat/packages.config": packagesConfigManifest},
			options: allProjects,
			cli:     []reportedAs{{"services/flat/packages.config", scanRootName}},
			scm:     []reportedAs{{"services/flat/packages.config", "flat"}},
		},
		{
			name:    "project.json beside a .csproj",
			files:   map[string]string{"services/app/project.json": projectJSONManifest, "services/app/App.csproj": csprojNet45},
			options: allProjects,
			cli:     []reportedAs{{"services/app/project.json", scanRootName}},
			scm:     []reportedAs{{"services/app/project.json", "app"}},
		},
		{
			name:    "project.json that names its project",
			files:   map[string]string{"services/app/project.json": namedProjectJSON, "services/app/App.csproj": csprojNet45},
			options: allProjects,
			cli:     []reportedAs{{"services/app/project.json", "FromProjectJSON"}},
			scm:     []reportedAs{{"services/app/project.json", "FromProjectJSON"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), scanRootName)
			for name, content := range tt.files {
				write(t, root, name, content)
			}
			dir := filepath.Join(root, tt.scanDir)

			scm := scan(t, dir, tt.options())
			cli := scan(t, dir, tt.options().WithCLIProjectIdentity(true))

			assert.ElementsMatch(t, tt.scm, identities(t, scm), "SCM identity")
			assert.ElementsMatch(t, tt.cli, identities(t, cli), "CLI identity")

			require.Len(t, cli, len(scm))
			for i := range scm {
				assert.Equal(t, scm[i].ProcessedFiles, cli[i].ProcessedFiles,
					"the identity must not change what a result claims, or the legacy resolver reports the project again")
				assert.Equal(t, scm[i].ProjectDescriptor.Identity.TargetRuntime, cli[i].ProjectDescriptor.Identity.TargetRuntime)
			}
		})
	}
}

// A filter that matches nothing reports its error against a project the scan
// found, so it must name that project the way a result for it would.
func TestPlugin_ProjectIdentityOfAFilterThatMatchedNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), scanRootName)
	write(t, root, "services/cart/Cart.csproj", csprojNet45)
	write(t, root, "services/cart/obj/project.assets.json", multiTargetAssets)

	options := allProjects().WithDotnetTargetFramework("net9.0").WithCLIProjectIdentity(true)

	results := scan(t, root, options)
	require.NotEmpty(t, results)

	last := results[len(results)-1]
	require.Error(t, last.Error)
	assert.Equal(t, reportedAs{"services/cart/obj/project.assets.json", scanRootName}, identities(t, results[len(results)-1:])[0])
}

func TestNewProjectNaming(t *testing.T) {
	t.Run("off by default", func(t *testing.T) {
		naming, err := newProjectNaming(t.TempDir(), ecosystems.NewPluginOptions())
		require.NoError(t, err)
		assert.Equal(t, projectNaming{}, naming)
	})

	t.Run("a relative scan root is named after the directory it resolves to", func(t *testing.T) {
		t.Chdir(t.TempDir())

		naming, err := newProjectNaming(".", ecosystems.NewPluginOptions().WithCLIProjectIdentity(true))
		require.NoError(t, err)

		cwd, err := filepath.Abs(".")
		require.NoError(t, err)
		assert.Equal(t, filepath.Base(cwd), naming.cliRootName)
	})

	// The filesystem root has no name, so a project there is named after its own
	// directory, as snyk-nuget-plugin's getRootName falls back to.
	t.Run("the filesystem root gives no name", func(t *testing.T) {
		naming, err := newProjectNaming(string(filepath.Separator), ecosystems.NewPluginOptions().WithCLIProjectIdentity(true))
		require.NoError(t, err)
		assert.True(t, naming.cli)
		assert.Empty(t, naming.cliRootName)
	})
}

func allProjects() *ecosystems.SCAPluginOptions {
	return ecosystems.NewPluginOptions().WithAllProjects(true)
}

func targetFile(path string) func() *ecosystems.SCAPluginOptions {
	return func() *ecosystems.SCAPluginOptions { return ecosystems.NewPluginOptions().WithTargetFile(path) }
}

func scan(t *testing.T, dir string, options *ecosystems.SCAPluginOptions) []ecosystems.SCAResult {
	t.Helper()

	results, err := scatest.Run(context.Background(), Plugin{}, logger.Nop(), dir, options)
	require.NoError(t, err)

	return results
}

// identities returns what each result is identified by, checking that the
// graph root agrees with the descriptor: the CLI names a project after one and
// SCM imports after the other.
func identities(t *testing.T, results []ecosystems.SCAResult) []reportedAs {
	t.Helper()

	out := make([]reportedAs, len(results))
	for i, r := range results {
		name := r.ProjectDescriptor.Identity.RootComponentName
		if r.DepGraph != nil {
			assert.Equal(t, name, r.DepGraph.GetRootPkg().Info.Name, "graph root and descriptor disagree")
		}
		out[i] = reportedAs{r.ProjectDescriptor.GetTargetFile(), name}
	}

	return out
}
