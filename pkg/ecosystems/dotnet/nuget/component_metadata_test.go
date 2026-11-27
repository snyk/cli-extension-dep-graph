package nuget

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// componentMetadataFixture is a real `dotnet restore` of a net8.0 project
// referencing Castle.Core 4.4.1, trimmed to two packages. See its README.md.
const componentMetadataFixture = "testdata/componentmetadata"

const (
	castleCore  = "castle.core/4.4.1"
	specialized = "system.collections.specialized/4.3.0"

	castleNodeID      = "Castle.Core@4.4.1"
	specializedNodeID = "System.Collections.Specialized@4.3.0"

	// castleCoreSHA512 is the SHA-512 of castle.core.4.4.1.nupkg as downloaded
	// from nuget.org's flat container on 2026-11-23, computed with
	// `openssl dgst -sha512`. The fixture's .nupkg.sha512 must decode to it.
	// libraries["Castle.Core/4.4.1"].sha512 in the assets file does not: that
	// is the content hash, which differs for a signed package.
	castleCoreSHA512 = "b27c340df07622abda8543a48c057eb936c9b02b7ed2d6f58e09e33bd5a5f70c" +
		"7a2ee867127a05697e5a4127ba40494a17ea40080482578328aa8a33ae97aa3a"

	castleCoreNuGetOrgURL = "https://api.nuget.org/v3-flatcontainer/castle.core/4.4.1/castle.core.4.4.1.nupkg"

	// standInNupkg stands in for a .nupkg where only its hash matters;
	// standInSHA512 is its SHA-512, computed with `openssl dgst -sha512`.
	standInNupkg  = "nupkg stand-in for component metadata tests\n"
	standInSHA512 = "d76304f264c5eb20b59213d67cea270e736f13b18f4cc97e6472d88898e44c3e" +
		"c383d8e38de9498e3a89c9eaf40f7359be7ebff6296142bbae3d25b146935f8f"

	customFeedIndex = "https://feed.example/nuget/v3/index.json"
)

// restoredProject lays the fixture's project out in a temp dir with its two
// packageFolders pointing at fresh temp folders, which it returns.
func restoredProject(t *testing.T) (dir, first, second string) {
	t.Helper()

	// Named, so the root is the same whichever temp dir holds it.
	dir = filepath.Join(t.TempDir(), "App")
	first = t.TempDir()
	second = t.TempDir()

	content, err := os.ReadFile(filepath.Join(componentMetadataFixture, objDir, projectAssetsFile))
	require.NoError(t, err)

	assets := strings.NewReplacer(
		"@PACKAGE_FOLDER_1@", jsonEscape(t, first),
		"@PACKAGE_FOLDER_2@", jsonEscape(t, second),
	).Replace(string(content))

	write(t, dir, filepath.Join(objDir, projectAssetsFile), assets)

	csproj, err := os.ReadFile(filepath.Join(componentMetadataFixture, "App.csproj"))
	require.NoError(t, err)
	write(t, dir, "App.csproj", string(csproj))

	return dir, first, second
}

func jsonEscape(t *testing.T, s string) string {
	t.Helper()

	quoted, err := json.Marshal(s)
	require.NoError(t, err)

	return string(quoted[1 : len(quoted)-1])
}

// install copies the fixture's restore sidecars for pkg (e.g.
// "castle.core/4.4.1") into a global packages folder.
func install(t *testing.T, folder, pkg string) string {
	t.Helper()

	source := filepath.Join(componentMetadataFixture, "packages", filepath.FromSlash(pkg))
	target := filepath.Join(folder, filepath.FromSlash(pkg))
	require.NoError(t, os.MkdirAll(target, 0o750))

	entries, err := os.ReadDir(source)
	require.NoError(t, err)

	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(source, entry.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(target, entry.Name()), content, 0o600))
	}

	return target
}

// writeSource rewrites the source a package's .nupkg.metadata records.
func writeSource(t *testing.T, pkgDir, source string) {
	t.Helper()

	metadata, err := json.Marshal(map[string]any{"version": 2, "contentHash": "irrelevant", "source": source})
	require.NoError(t, err)
	write(t, pkgDir, nupkgMetadataFile, string(metadata))
}

func withMetadata() *ecosystems.SCAPluginOptions {
	return ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true)
}

func scanWith(t *testing.T, plugin Plugin, dir string, options *ecosystems.SCAPluginOptions) *godepgraph.DepGraph {
	t.Helper()

	results, err := scatest.Run(t.Context(), plugin, logger.Nop(), dir, options)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	require.NotNil(t, results[0].DepGraph)

	return results[0].DepGraph
}

// labelsByNode returns every node's labels, nil for a node with none.
func labelsByNode(graph *godepgraph.DepGraph) map[string]map[string]string {
	labels := make(map[string]map[string]string, len(graph.Graph.Nodes))
	for _, node := range graph.Graph.Nodes {
		if node.Info == nil {
			labels[node.NodeID] = nil
			continue
		}
		labels[node.NodeID] = node.Info.Labels
	}
	return labels
}

func graphJSON(t *testing.T, graph *godepgraph.DepGraph) string {
	t.Helper()

	out, err := json.Marshal(graph)
	require.NoError(t, err)

	return string(out)
}

// object returns the JSON object at a path of keys.
func object(t *testing.T, root map[string]any, keys ...string) map[string]any {
	t.Helper()

	current := root
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		require.True(t, ok, "no object at %q", key)
		current = next
	}

	return current
}

// editAssets rewrites the project's assets file through its decoded JSON.
func editAssets(t *testing.T, dir string, edit func(assets map[string]any)) {
	t.Helper()

	path := filepath.Join(dir, objDir, projectAssetsFile)
	content, err := os.ReadFile(path)
	require.NoError(t, err)

	var assets map[string]any
	require.NoError(t, json.Unmarshal(content, &assets))
	edit(assets)

	out, err := json.Marshal(assets)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, out, 0o600))
}

func fileSHA512(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha512.Sum512(content)

	return hex.EncodeToString(sum[:])
}

func TestComponentMetadata_FlagOffLeavesOutputUnchanged(t *testing.T) {
	t.Run("PackageReference", func(t *testing.T) {
		bare, _, _ := restoredProject(t)
		restored, first, _ := restoredProject(t)
		install(t, first, castleCore)
		install(t, first, specialized)

		without := graphJSON(t, scanWith(t, Plugin{}, bare, ecosystems.NewPluginOptions()))
		with := graphJSON(t, scanWith(t, Plugin{}, restored, ecosystems.NewPluginOptions()))

		assert.Equal(t, without, with)
		assert.NotContains(t, with, "hash:")
		assert.NotContains(t, with, "distribution:url")
	})

	t.Run("packages.config", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, packagesConfigFile, packagesConfigManifest)
		folder := filepath.Join(dir, packagesFolderName)
		writeNupkg(t, folder, declaredPackage{"jQuery", "3.2.1"}, zipEntry{"jQuery.nuspec", []byte(nuspecWith(""))})

		options := ecosystems.NewPluginOptions().WithPackagesFolder(folder)
		graph := scanWith(t, Plugin{}, dir, options)

		assert.NotContains(t, graphJSON(t, graph), "hash:")
	})
}

func TestComponentMetadata_SHA512Sidecar(t *testing.T) {
	t.Run("found in the first package folder", func(t *testing.T) {
		dir, first, _ := restoredProject(t)
		install(t, first, castleCore)
		install(t, first, specialized)

		labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

		assert.Equal(t, map[string]string{
			"hash:sha-512":     castleCoreSHA512,
			"distribution:url": castleCoreNuGetOrgURL,
		}, labels[castleNodeID])
		assert.Equal(t, map[string]string{
			// SHA-512 of the restored .nupkg, computed with openssl.
			"hash:sha-512": "c7a257cbda812d6c0c44b29d8bb5cc4f5cf2d3cb81574eb1dc94a7efde980ac2" +
				"6c5ffadb7cc3521fe7b19437766a046c83cbf2e7ea59a36435c288add8142b57",
			"distribution:url": "https://api.nuget.org/v3-flatcontainer/system.collections.specialized/4.3.0/" +
				"system.collections.specialized.4.3.0.nupkg",
		}, labels[specializedNodeID])
		assert.Nil(t, labels["root-node"], "the root is the project, not a package")
	})

	t.Run("found in the second package folder", func(t *testing.T) {
		dir, first, second := restoredProject(t)
		// The first folder holds the package without its .sha512; the search
		// for the sidecar still runs through every folder before falling back
		// to hashing a .nupkg.
		write(t, filepath.Join(first, filepath.FromSlash(castleCore)), "castle.core.4.4.1"+nupkgExt, standInNupkg)
		install(t, second, castleCore)

		labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

		assert.Equal(t, castleCoreSHA512, labels[castleNodeID]["hash:sha-512"])
		assert.Equal(t, castleCoreNuGetOrgURL, labels[castleNodeID]["distribution:url"])
	})

	t.Run("a malformed sidecar falls back to the .nupkg beside it", func(t *testing.T) {
		dir, first, _ := restoredProject(t)
		pkgDir := install(t, first, castleCore)
		write(t, pkgDir, "castle.core.4.4.1"+sha512SidecarExt, "not base64!")
		write(t, pkgDir, "castle.core.4.4.1"+nupkgExt, standInNupkg)

		labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

		assert.Equal(t, standInSHA512, labels[castleNodeID]["hash:sha-512"])
	})

	// The first folder's malformed sidecar must not hide the second folder's
	// valid one, and the URL comes from the folder the hash came from.
	t.Run("a malformed sidecar in the first folder does not hide a valid one in the second", func(t *testing.T) {
		dir, first, second := restoredProject(t)
		firstDir := install(t, first, castleCore)
		write(t, firstDir, "castle.core.4.4.1"+sha512SidecarExt, "not base64!")
		writeSource(t, firstDir, customFeedIndex)
		install(t, second, castleCore)

		labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

		assert.Equal(t, map[string]string{
			"hash:sha-512":     castleCoreSHA512,
			"distribution:url": castleCoreNuGetOrgURL,
		}, labels[castleNodeID])
	})

	t.Run("a malformed sidecar with no .nupkg gives no hash", func(t *testing.T) {
		dir, first, _ := restoredProject(t)
		write(t, install(t, first, castleCore), "castle.core.4.4.1"+sha512SidecarExt, "c2hvcnQ=")

		labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

		assert.Equal(t, map[string]string{"distribution:url": castleCoreNuGetOrgURL}, labels[castleNodeID])
	})
}

func TestComponentMetadata_NupkgFallback(t *testing.T) {
	dir, _, second := restoredProject(t)
	write(t, filepath.Join(second, filepath.FromSlash(castleCore)), "castle.core.4.4.1"+nupkgExt, standInNupkg)

	labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

	// No .nupkg.metadata beside it, so no URL: only the hash is known.
	assert.Equal(t, map[string]string{"hash:sha-512": standInSHA512}, labels[castleNodeID])
}

func TestComponentMetadata_NothingInstalled(t *testing.T) {
	dir, first, _ := restoredProject(t)
	// Metadata alone is not an artifact: without the package file or its hash
	// there is nothing the labels would describe.
	writeSource(t, filepath.Join(first, filepath.FromSlash(castleCore)), "https://api.nuget.org/v3/index.json")

	labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

	assert.Nil(t, labels[castleNodeID])
	assert.Nil(t, labels[specializedNodeID])
}

// D1: a .nupkg that is a device rather than a file, beside a sidecar that
// fails to decode, sent the .nupkg fallback into an endless read. Only regular
// files are read.
func TestComponentMetadata_NonRegularFilesAreNotRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /dev/zero")
	}

	dir, first, _ := restoredProject(t)
	pkgDir := install(t, first, castleCore)
	write(t, pkgDir, "castle.core.4.4.1"+sha512SidecarExt, "garbage")
	require.NoError(t, os.Symlink("/dev/zero", filepath.Join(pkgDir, "castle.core.4.4.1"+nupkgExt)))

	done := make(chan map[string]map[string]string, 1)
	go func() {
		results, err := scatest.Run(t.Context(), Plugin{}, logger.Nop(), dir, withMetadata())
		if err != nil || len(results) != 1 || results[0].DepGraph == nil {
			done <- nil
			return
		}
		done <- labelsByNode(results[0].DepGraph)
	}()

	select {
	case labels := <-done:
		require.NotNil(t, labels)
		assert.Equal(t, map[string]string{"distribution:url": castleCoreNuGetOrgURL}, labels[castleNodeID])
	case <-time.After(10 * time.Second):
		t.Fatal("the scan did not finish: a non-regular .nupkg was read")
	}
}

// Real assets files record absolute package folders. A relative one would
// resolve against the CLI's working directory, which the scanned repository
// controls, so it is skipped.
func TestComponentMetadata_RelativePackageFolderIsSkipped(t *testing.T) {
	dir, _, _ := restoredProject(t)
	install(t, dir, castleCore)
	t.Chdir(dir)
	editAssets(t, dir, func(assets map[string]any) {
		assets["packageFolders"] = map[string]any{".": map[string]any{}}
	})

	labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

	assert.Nil(t, labels[castleNodeID])
}

// A project reference shares the targets layout with packages, and may share a
// published package's name and version; it has no .nupkg of its own.
func TestComponentMetadata_ProjectReferencesAreNotLabeled(t *testing.T) {
	dir, first, _ := restoredProject(t)
	install(t, first, castleCore)
	install(t, first, specialized)
	editAssets(t, dir, func(assets map[string]any) {
		object(t, assets, "libraries")["Castle.Core/4.4.1"] = map[string]any{
			"type":           "project",
			"path":           "../Castle.Core/Castle.Core.csproj",
			"msbuildProject": "../Castle.Core/Castle.Core.csproj",
		}
	})

	labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

	assert.Nil(t, labels[castleNodeID])
	assert.NotEmpty(t, labels[specializedNodeID]["hash:sha-512"])
}

// packages.config and project.json folders are hash-only: NuGet writes
// .nupkg.metadata only into the v3 global packages folder.
func TestComponentMetadata_PackagesConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, packagesConfigFile, packagesConfigManifest)
	folder := filepath.Join(dir, packagesFolderName)

	jquery := declaredPackage{"jQuery", "3.2.1"}
	writeNupkg(t, folder, jquery, zipEntry{"jQuery.nuspec", []byte(nuspecWith(""))})

	options := ecosystems.NewPluginOptions().WithPackagesFolder(folder).WithIncludeComponentMetadata(true)
	labels := labelsByNode(scanWith(t, Plugin{}, dir, options))

	assert.Equal(t, map[string]string{
		"hash:sha-512": fileSHA512(t, filepath.Join(packageDir(folder, jquery), "jQuery.3.2.1.nupkg")),
	}, labels["jQuery@3.2.1"])
	assert.Nil(t, labels["Newtonsoft.Json@10.0.3"], "declared but not installed")
}

func TestComponentMetadata_DistributionURL(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantURL string
	}{
		{"nuget.org gets its file URL, whatever the host's case", "https://API.nuget.org/v3/index.json", castleCoreNuGetOrgURL},
		{"another feed gets its service index", customFeedIndex, customFeedIndex},
		{"credentials, query and fragment are stripped", "https://u:p@feed.example/nuget/v3/index.json?code=abc#x", customFeedIndex},
		{"a feed key in the path gives no URL", "https://feed.example/F/team/auth/KEY/api/v3/index.json", ""},
		{"a local folder feed gives no URL", "/home/build/local-feed", ""},
		{"a Windows share gives no URL", `\\fileserver\nuget`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, first, _ := restoredProject(t)
			writeSource(t, install(t, first, castleCore), tt.source)

			labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

			want := map[string]string{"hash:sha-512": castleCoreSHA512}
			if tt.wantURL != "" {
				want["distribution:url"] = tt.wantURL
			}
			assert.Equal(t, want, labels[castleNodeID])
		})
	}

	t.Run("an unparseable .nupkg.metadata gives no URL", func(t *testing.T) {
		dir, first, _ := restoredProject(t)
		write(t, install(t, first, castleCore), nupkgMetadataFile, "{not json")

		labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

		assert.Equal(t, map[string]string{"hash:sha-512": castleCoreSHA512}, labels[castleNodeID])
	})
}

// A pruned node is a stub pointing back at a package already in the graph, and
// carries only its `pruned` label, as snyk-mvn-plugin's do. The full node holds
// the metadata, and sbom-export folds a pruned stub into it.
func TestComponentMetadata_PrunedNodesStayStubs(t *testing.T) {
	dir, first, _ := restoredProject(t)
	install(t, first, castleCore)
	install(t, first, specialized)
	editAssets(t, dir, func(assets map[string]any) {
		// Close a cycle: System.Collections.Specialized depends back on Castle.Core.
		object(t, assets, "targets", "net8.0", "System.Collections.Specialized/4.3.0")["dependencies"] = map[string]any{"Castle.Core": "4.4.1"}
	})

	labels := labelsByNode(scanWith(t, Plugin{}, dir, withMetadata()))

	assert.Equal(t, map[string]string{prunedLabelKey: prunedLabelValue}, labels[castleNodeID+prunedNodeSuffix])
	assert.Equal(t, castleCoreSHA512, labels[castleNodeID]["hash:sha-512"])
}

func TestComponentMetadata_Deterministic(t *testing.T) {
	dir, first, _ := restoredProject(t)
	writeSource(t, install(t, first, castleCore), customFeedIndex)
	install(t, first, specialized)

	want := graphJSON(t, scanWith(t, Plugin{}, dir, withMetadata()))
	for range 5 {
		assert.Equal(t, want, graphJSON(t, scanWith(t, Plugin{}, dir, withMetadata())))
	}
}

// Ids and versions come from files in the scanned repository, so one that
// would step out of the package folder is never looked up.
func TestGlobalPackageLabels_RejectsPathSegments(t *testing.T) {
	folder := t.TempDir()
	labeler := newComponentLabeler(logger.Nop())

	for _, pkg := range [][2]string{{"..", "."}, {"a/b", "1.0.0"}, {`a\b`, "1.0.0"}, {"a", ""}} {
		assert.Nil(t, labeler.globalPackageLabels(t.Context(), []string{folder}, pkg[0], pkg[1]), "%s %s", pkg[0], pkg[1])
	}
}

func TestFileSHA512Hex_StopsWhenContextIsDone(t *testing.T) {
	path := write(t, t.TempDir(), "pkg"+nupkgExt, standInNupkg)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := fileSHA512Hex(ctx, path)
	require.ErrorIs(t, err, context.Canceled)

	digest, err := fileSHA512Hex(t.Context(), path)
	require.NoError(t, err)
	assert.Equal(t, standInSHA512, digest)
}

func TestReadRegularFile_RejectsOversizedFiles(t *testing.T) {
	path := write(t, t.TempDir(), "x"+sha512SidecarExt, strings.Repeat("A", maxSidecarBytes+1))

	_, err := readRegularFile(path, maxSidecarBytes)
	assert.Error(t, err)
}
