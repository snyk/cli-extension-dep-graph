package uv

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

const (
	idnaWheelURL  = "https://files.pythonhosted.org/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl"
	idnaWheelHash = "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c"
	charsetURL    = "https://files.pythonhosted.org/packages/d2/0d/07ab8eb9b7015274353eac2add4067bde1ab1b51912bbae505392905eedd/" +
		"charset_normalizer-3.5.3-py3-none-any.whl"
	charsetHash    = "96e268b0cbda016ac519513294fcd17032264085b600abaac58b93049477e132"
	pyyamlSdistURL = "https://files.pythonhosted.org/packages/54/ed/79a089b6be93607fa5cdaedf301d7dfb23af5f25c398d5ead2525b063e17/pyyaml-6.0.2.tar.gz"
	pyyamlHash     = "d584d9ec91ad65861cc08d42e834324ef890a082e591037abe114850ff7bbc3e"
	sixWheelURL    = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl"
	sixWheelHash   = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"
)

func recordedExport(t *testing.T, name string) Sbom {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "componentmetadata", name))
	require.NoError(t, err)
	return data
}

// node describes one dep-graph node as the converter names it: the node ID
// may carry a "|n" suffix, and the package name is whatever the SBOM said.
type node struct {
	id, name, version string
	pruned            bool
}

// graphOf builds a graph the way the converter shapes one: package IDs are
// name@version, the root depends on every other node.
func graphOf(root node, deps ...node) *depgraph.DepGraph {
	dg := &depgraph.DepGraph{
		SchemaVersion: "1.3.0",
		PkgManager:    depgraph.PkgManager{Name: "uv"},
		Graph:         depgraph.Graph{RootNodeID: root.id},
	}
	seen := map[string]bool{}
	add := func(n node) depgraph.Node {
		pkgID := n.name + "@" + n.version
		if !seen[pkgID] {
			seen[pkgID] = true
			dg.Pkgs = append(dg.Pkgs, depgraph.Pkg{ID: pkgID, Info: depgraph.PkgInfo{Name: n.name, Version: n.version}})
		}
		gn := depgraph.Node{NodeID: n.id, PkgID: pkgID, Deps: []depgraph.Dependency{}}
		if n.pruned {
			gn.Info = &depgraph.NodeInfo{Labels: map[string]string{"pruned": "true"}}
		}
		return gn
	}
	rootNode := add(root)
	nodes := make([]depgraph.Node, 0, len(deps))
	for _, d := range deps {
		rootNode.Deps = append(rootNode.Deps, depgraph.Dependency{NodeID: d.id})
		nodes = append(nodes, add(d))
	}
	dg.Graph.Nodes = append([]depgraph.Node{rootNode}, nodes...)
	return dg
}

func extrasGraph() *depgraph.DepGraph {
	return graphOf(node{id: "extras-probe@0.1.0", name: "extras-probe", version: "0.1.0"},
		node{id: "requests@2.32.3", name: "requests", version: "2.32.3"},
		node{id: "idna@3.20", name: "idna", version: "3.20"},
		node{id: "charset-normalizer@3.5.3", name: "charset-normalizer", version: "3.5.3"},
		node{id: "pysocks@1.7.1", name: "pysocks", version: "1.7.1"},
	)
}

func scanWith(
	t *testing.T, sbom Sbom, uvVersion string, includeMetadata bool, graphs ...*depgraph.DepGraph,
) []ecosystems.SCAResult {
	t.Helper()
	dir := createFiles(t, "uv.lock", "pyproject.toml")
	client := &MockClient{SBOM: sbom, UvVersion: uvVersion}
	opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(includeMetadata).WithAllProjects(true)
	results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(graphs...), ""), testLogger, dir, opts)
	require.NoError(t, err)
	for _, r := range results {
		require.NoError(t, r.Error)
	}
	return results
}

// labelsByNode returns every node's labels across the results, keyed by
// graph root and node ID; nodes without labels are left out.
func labelsByNode(results []ecosystems.SCAResult) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, r := range results {
		for _, n := range r.DepGraph.Graph.Nodes {
			if n.Info != nil && len(n.Info.Labels) > 0 {
				out[n.NodeID] = n.Info.Labels
			}
		}
	}
	return out
}

func artifactLabels(url, sha256 string) map[string]string {
	return map[string]string{"hash:sha-256": sha256, "distribution:url": url}
}

func marshalGraphs(t *testing.T, graphs []*depgraph.DepGraph) string {
	t.Helper()
	data, err := json.Marshal(graphs)
	require.NoError(t, err)
	return string(data)
}

func TestComponentMetadata_FlagOffLeavesGraphsUnchanged(t *testing.T) {
	want := marshalGraphs(t, []*depgraph.DepGraph{extrasGraph()})

	results := scanWith(t, recordedExport(t, "extras-0.12.22.json"), "0.12.22", false, extrasGraph())

	require.Len(t, results, 1)
	assert.Equal(t, want, marshalGraphs(t, []*depgraph.DepGraph{results[0].DepGraph}))
}

func TestComponentMetadata_LabelsFromRecordedExport(t *testing.T) {
	results := scanWith(t, recordedExport(t, "extras-0.12.22.json"), "0.12.22", true, extrasGraph())

	got := labelsByNode(results)
	assert.Equal(t, artifactLabels(idnaWheelURL, idnaWheelHash), got["idna@3.20"], "the universal wheel")
	assert.Equal(t, artifactLabels(charsetURL, charsetHash), got["charset-normalizer@3.5.3"],
		"the universal wheel among an sdist and 150-odd platform wheels")
	assert.Contains(t, got, "requests@2.32.3")
	assert.Contains(t, got, "pysocks@1.7.1")
	assert.NotContains(t, got, "extras-probe@0.1.0", "the project itself lists no distribution")
}

// TestComponentMetadata_JoinsOnRecordedConverterOutput runs the join against
// the remote converter's real response for extras-0.12.22.json rather than a
// hand-built graph, so a change in how the converter names packages breaks
// this test instead of silently dropping labels.
func TestComponentMetadata_JoinsOnRecordedConverterOutput(t *testing.T) {
	var graphs []*depgraph.DepGraph
	require.NoError(t, json.Unmarshal(recordedExport(t, "extras-0.12.22.converted.json"), &graphs))
	require.Len(t, graphs, 1)

	results := scanWith(t, recordedExport(t, "extras-0.12.22.json"), "0.12.22", true, graphs...)

	got := labelsByNode(results)
	for _, n := range graphs[0].Graph.Nodes {
		if n.NodeID == graphs[0].Graph.RootNodeID {
			assert.NotContains(t, got, n.NodeID, "the project itself lists no distribution")
			continue
		}
		assert.Contains(t, got, n.NodeID, "every registry package joins to its export component")
	}
	assert.Equal(t, artifactLabels(idnaWheelURL, idnaWheelHash), got["idna@3.20"])
	assert.Equal(t, artifactLabels(charsetURL, charsetHash), got["charset-normalizer@3.5.3"])
}

func TestComponentMetadata_WorkspaceSdistFallbackAndLocalSources(t *testing.T) {
	graphs := []*depgraph.DepGraph{
		graphOf(node{id: "member-a@0.1.0", name: "member-a", version: "0.1.0"},
			node{id: "idna@3.10", name: "idna", version: "3.10"},
			node{id: "local-dep@1.0.0", name: "local-dep", version: "1.0.0"},
			node{id: "pyyaml@6.0.2", name: "pyyaml", version: "6.0.2"},
		),
		graphOf(node{id: "member-b@0.1.0", name: "member-b", version: "0.1.0"},
			node{id: "member-a@0.1.0", name: "member-a", version: "0.1.0"},
			node{id: "six@1.16.0", name: "six", version: "1.16.0"},
		),
	}

	results := scanWith(t, recordedExport(t, "workspace-all-packages-0.12.22.json"), "0.12.22", true, graphs...)

	require.Len(t, results, 2)
	got := labelsByNode(results)
	assert.Equal(t, artifactLabels(pyyamlSdistURL, pyyamlHash), got["pyyaml@6.0.2"], "no universal wheel, so the sdist")
	assert.Equal(t, artifactLabels(sixWheelURL, sixWheelHash), got["six@1.16.0"])
	assert.Contains(t, got, "idna@3.10")
	assert.NotContains(t, got, "local-dep@1.0.0", "a path source has no distribution")
	assert.NotContains(t, got, "member-a@0.1.0", "a workspace member has no distribution")
	assert.NotContains(t, got, "member-b@0.1.0")
}

func TestComponentMetadata_UvBefore0125GetsNoLabels(t *testing.T) {
	tests := []struct {
		name      string
		export    string
		uvVersion string
	}{
		{name: "export from uv 0.12.4 lists no distributions", export: "extras-0.12.4.json", uvVersion: "0.12.4"},
		{name: "the version gates, not the export's content", export: "extras-0.12.22.json", uvVersion: "0.12.4"},
		{name: "an unknown version gets no labels", export: "extras-0.12.22.json", uvVersion: ""},
		{name: "older minor", export: "extras-0.12.22.json", uvVersion: "0.11.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := marshalGraphs(t, []*depgraph.DepGraph{extrasGraph()})

			results := scanWith(t, recordedExport(t, tt.export), tt.uvVersion, true, extrasGraph())

			require.Len(t, results, 1)
			assert.Equal(t, want, marshalGraphs(t, []*depgraph.DepGraph{results[0].DepGraph}))
		})
	}
}

func TestComponentMetadata_LogsWhyUvIsTooOld(t *testing.T) {
	dir := createFiles(t, "uv.lock", "pyproject.toml")
	client := &MockClient{SBOM: recordedExport(t, "extras-0.12.4.json"), UvVersion: "0.12.4"}
	log := &recordingLogger{}
	opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true)

	_, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(extrasGraph()), ""), log, dir, opts)

	require.NoError(t, err)
	assert.True(t, log.contains("0.12.5"), "the log names the uv version labels need: %v", log.messages)
}

// syntheticExport wraps components in a minimal uv export.
func syntheticExport(components ...string) Sbom {
	return Sbom(`{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"metadata":{"component":{"bom-ref":"proj-1@1.0.0","name":"proj","version":"1.0.0",` +
		`"properties":[{"name":"uv:package:is_project_root","value":"true"}]}},` +
		`"components":[` + strings.Join(components, ",") + `]}`)
}

type dist struct{ url, sha256 string }

func component(name, version string, dists ...dist) string {
	refs := make([]string, 0, len(dists))
	for _, d := range dists {
		refs = append(refs, `{"type":"distribution","url":"`+d.url+`","hashes":[{"alg":"SHA-256","content":"`+d.sha256+`"}]}`)
	}
	return `{"type":"library","bom-ref":"` + name + `-2@` + version + `","name":"` + name + `","version":"` + version +
		`","purl":"pkg:pypi/` + name + `@` + version + `","externalReferences":[` + strings.Join(refs, ",") + `]}`
}

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func projGraph(deps ...node) *depgraph.DepGraph {
	return graphOf(node{id: "proj@1.0.0", name: "proj", version: "1.0.0"}, deps...)
}

func TestComponentMetadata_ArtifactSelection(t *testing.T) {
	tests := []struct {
		name  string
		dists []dist
		want  map[string]string
	}{
		{
			name: "universal wheel over sdist and platform wheels",
			dists: []dist{
				{"https://feed.example/f/foo-1.0.tar.gz", hashA},
				{"https://feed.example/f/foo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", hashB},
				{"https://feed.example/f/foo-1.0-py3-none-any.whl", hashC},
			},
			want: artifactLabels("https://feed.example/f/foo-1.0-py3-none-any.whl", hashC),
		},
		{
			name: "sdist when every wheel is platform-specific",
			dists: []dist{
				{"https://feed.example/f/foo-1.0-cp312-cp312-win_amd64.whl", hashB},
				{"https://feed.example/f/foo-1.0.tar.gz", hashA},
			},
			want: artifactLabels("https://feed.example/f/foo-1.0.tar.gz", hashA),
		},
		{
			name: "only platform wheels: nothing is guessed",
			dists: []dist{
				{"https://feed.example/f/foo-1.0-cp312-cp312-win_amd64.whl", hashA},
				{"https://feed.example/f/foo-1.0-cp312-cp312-macosx_11_0_arm64.whl", hashB},
			},
			want: nil,
		},
		{
			name:  "a single file is used as is",
			dists: []dist{{"https://feed.example/f/foo-1.0-cp312-cp312-win_amd64.whl", hashA}},
			want:  artifactLabels("https://feed.example/f/foo-1.0-cp312-cp312-win_amd64.whl", hashA),
		},
		{
			name:  "the filename is URL-decoded before matching",
			dists: []dist{{"https://feed.example/f/foo-1.0.tar.gz", hashA}, {"https://feed.example/f/foo-1.0-py3-none-any%2Ewhl", hashC}},
			want:  artifactLabels("https://feed.example/f/foo-1.0-py3-none-any%2Ewhl", hashC),
		},
		{
			name:  "credentials, query and fragment are stripped from the URL",
			dists: []dist{{"https://u:p@feed.example/f/foo-1.0-py3-none-any.whl?x=1#sha256=" + hashA, hashA}},
			want:  artifactLabels("https://feed.example/f/foo-1.0-py3-none-any.whl", hashA),
		},
		{
			name:  "a URL with an auth segment is dropped, the hash kept",
			dists: []dist{{"https://feed.example/F/team/auth/key/foo-1.0-py3-none-any.whl", hashA}},
			want:  map[string]string{"hash:sha-256": hashA},
		},
		{
			name:  "a non-hex digest is dropped, the URL kept",
			dists: []dist{{"https://feed.example/f/foo-1.0-py3-none-any.whl", "not-hex"}},
			want:  map[string]string{"distribution:url": "https://feed.example/f/foo-1.0-py3-none-any.whl"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom := syntheticExport(component("foo", "1.0", tt.dists...))

			results := scanWith(t, sbom, "0.12.5", true, projGraph(node{id: "foo@1.0", name: "foo", version: "1.0"}))

			assert.Equal(t, tt.want, labelsByNode(results)["foo@1.0"])
		})
	}
}

func TestComponentMetadata_JoinsOnNormalisedNameAndExactVersion(t *testing.T) {
	sbom := syntheticExport(component("foo-bar", "1.0", dist{"https://feed.example/f/foo_bar-1.0-py3-none-any.whl", hashA}))
	graph := projGraph(
		node{id: "Foo_Bar@1.0|1", name: "Foo_Bar", version: "1.0"},
		node{id: "Foo_Bar@1.0|2", name: "Foo_Bar", version: "1.0"},
		node{id: "foo.bar@1.0.0", name: "foo.bar", version: "1.0.0"},
		node{id: "foo-bar@1.0:pruned", name: "foo-bar", version: "1.0", pruned: true},
	)

	results := scanWith(t, sbom, "0.12.22", true, graph)

	got := labelsByNode(results)
	want := artifactLabels("https://feed.example/f/foo_bar-1.0-py3-none-any.whl", hashA)
	assert.Equal(t, want, got["Foo_Bar@1.0|1"], "names match after PEP 503 normalisation")
	assert.Equal(t, want, got["Foo_Bar@1.0|2"], "every occurrence of a package is labeled")
	assert.NotContains(t, got, "foo.bar@1.0.0", "versions match exactly, not as equal PEP 440 versions")
	assert.Equal(t, map[string]string{"pruned": "true"}, got["foo-bar@1.0:pruned"], "a pruned stub keeps only its pruned label")
}

func TestComponentMetadata_ConflictingDuplicatesGetNoLabels(t *testing.T) {
	sbom := syntheticExport(
		component("foo_bar", "1.0", dist{"https://feed.example/f/foo_bar-1.0-py3-none-any.whl", hashA}),
		component("Foo.Bar", "1.0", dist{"https://other.example/f/foo_bar-1.0-py3-none-any.whl", hashB}),
		component("same", "2.0", dist{"https://feed.example/f/same-2.0-py3-none-any.whl", hashC}),
		component("same", "2.0", dist{"https://feed.example/f/same-2.0-py3-none-any.whl", hashC}),
		component("mixed", "3.0", dist{"https://feed.example/f/mixed-3.0-py3-none-any.whl", hashC}),
		component("mixed", "3.0"),
	)
	graph := projGraph(
		node{id: "foo-bar@1.0", name: "foo-bar", version: "1.0"},
		node{id: "same@2.0", name: "same", version: "2.0"},
		node{id: "mixed@3.0", name: "mixed", version: "3.0"},
	)

	results := scanWith(t, sbom, "0.12.22", true, graph)

	got := labelsByNode(results)
	assert.NotContains(t, got, "foo-bar@1.0", "two artifacts for one name@version: neither is labeled")
	assert.NotContains(t, got, "mixed@3.0", "one source with a distribution, one without: neither is labeled")
	assert.Equal(t, artifactLabels("https://feed.example/f/same-2.0-py3-none-any.whl", hashC), got["same@2.0"],
		"duplicates that agree are labeled")
}

// The project's own name@version can collide with a registry package; its
// node must not take that package's labels.
func TestComponentMetadata_RootComponentTakesPartInConflicts(t *testing.T) {
	sbom := syntheticExport(component("proj", "1.0.0", dist{"https://feed.example/f/proj-1.0.0-py3-none-any.whl", hashA}))

	results := scanWith(t, sbom, "0.12.22", true, projGraph(node{id: "x@1", name: "x", version: "1"}))

	assert.Empty(t, labelsByNode(results))
}

func TestComponentMetadata_UnreadableReferencesLeaveGraphsUnlabeled(t *testing.T) {
	sbom := Sbom(`{"metadata":{"component":{"name":"proj","version":"1.0.0",` +
		`"properties":[{"name":"uv:package:is_project_root","value":"true"}]}},` +
		`"components":[{"name":"foo","version":"1.0","externalReferences":"not-a-list"}]}`)
	want := marshalGraphs(t, []*depgraph.DepGraph{projGraph(node{id: "foo@1.0", name: "foo", version: "1.0"})})

	results := scanWith(t, sbom, "0.12.22", true, projGraph(node{id: "foo@1.0", name: "foo", version: "1.0"}))

	require.Len(t, results, 1)
	assert.Equal(t, want, marshalGraphs(t, []*depgraph.DepGraph{results[0].DepGraph}))
}

func TestSupportsComponentMetadata(t *testing.T) {
	for version, want := range map[string]bool{
		"0.12.5": true, "0.12.22": true, "0.13.0": true, "1.0.0": true,
		"0.12.4": false, "0.9.29": false, "": false, "dev": false,
	} {
		assert.Equal(t, want, supportsComponentMetadata(version), version)
	}
}

type recordingLogger struct {
	messages []string
}

func (r *recordingLogger) record(msg string, fields []logger.Field) {
	parts := []string{msg}
	for _, f := range fields {
		if s, ok := f.Value.(string); ok {
			parts = append(parts, f.Key+"="+s)
		}
	}
	r.messages = append(r.messages, strings.Join(parts, " "))
}

func (r *recordingLogger) Info(_ context.Context, msg string, fields ...logger.Field) {
	r.record(msg, fields)
}

func (r *recordingLogger) Debug(_ context.Context, msg string, fields ...logger.Field) {
	r.record(msg, fields)
}

func (r *recordingLogger) Error(_ context.Context, msg string, fields ...logger.Field) {
	r.record(msg, fields)
}

func (r *recordingLogger) contains(s string) bool {
	for _, m := range r.messages {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

func TestArtifactFilename(t *testing.T) {
	for rawURL, want := range map[string]string{
		"https://feed.example/f/foo-1.0.tar.gz":          "foo-1.0.tar.gz",
		"https://feed.example/f/foo%2B1-1.0.tar.gz":      "foo+1-1.0.tar.gz",
		"https://feed.example/f/a%2Ffoo-1.0.tar.gz":      "a/foo-1.0.tar.gz",
		"https://feed.example/f/foo-1.0.tar.gz?x=1#frag": "foo-1.0.tar.gz",
		"https://[::1": "",
	} {
		assert.Equal(t, want, artifactFilename(rawURL), rawURL)
	}
}

func TestComponentMetadata_LogsWhenTheUvVersionIsUnreadable(t *testing.T) {
	for name, client := range map[string]*MockClient{
		"version error":                {VersionErr: errors.New("boom")},
		"version error beside a value": {UvVersion: "0.12.22", VersionErr: errors.New("boom")},
		"empty version":                {},
	} {
		t.Run(name, func(t *testing.T) {
			dir := createFiles(t, "uv.lock", "pyproject.toml")
			client.SBOM = recordedExport(t, "extras-0.12.22.json")
			log := &recordingLogger{}
			opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true)

			results, err := scatest.Run(t.Context(), NewPlugin(client, mockConverter(extrasGraph()), ""), log, dir, opts)

			require.NoError(t, err)
			assert.Empty(t, labelsByNode(results))
			assert.True(t, log.contains("the uv version; no component hashes emitted"), "%v", log.messages)
			assert.False(t, log.contains("exports artifact hashes from"), "not reported as too old: %v", log.messages)
		})
	}
}

// One component that cannot be read loses its own labels, not everyone's.
func TestComponentMetadata_MalformedComponentIsIsolated(t *testing.T) {
	sbom := syntheticExport(
		`{"name":"bad","version":"1.0","externalReferences":"not-a-list"}`,
		`{"name":"worse","version":"1.0","externalReferences":[{"type":"distribution","url":7}]}`,
		component("foo", "1.0", dist{"https://feed.example/f/foo-1.0-py3-none-any.whl", hashA}),
	)
	graph := projGraph(
		node{id: "bad@1.0", name: "bad", version: "1.0"},
		node{id: "worse@1.0", name: "worse", version: "1.0"},
		node{id: "foo@1.0", name: "foo", version: "1.0"},
	)

	results := scanWith(t, sbom, "0.12.22", true, graph)

	got := labelsByNode(results)
	assert.Equal(t, artifactLabels("https://feed.example/f/foo-1.0-py3-none-any.whl", hashA), got["foo@1.0"])
	assert.NotContains(t, got, "bad@1.0")
	assert.NotContains(t, got, "worse@1.0")
}

// A malformed component can still be told apart by name and version: it must
// still veto a same-named component's labels, since its artifact is unknown.
func TestComponentMetadata_MalformedDuplicateStillConflicts(t *testing.T) {
	sbom := syntheticExport(
		`{"name":"foo","version":"1.0","externalReferences":"not-a-list"}`,
		component("foo", "1.0", dist{"https://feed.example/f/foo-1.0-py3-none-any.whl", hashA}),
	)

	results := scanWith(t, sbom, "0.12.22", true, projGraph(node{id: "foo@1.0", name: "foo", version: "1.0"}))

	assert.Empty(t, labelsByNode(results))
}

func TestLabelComponents_UnreadableExportLeavesGraphsAlone(t *testing.T) {
	for name, sbom := range map[string]Sbom{
		"not JSON":                Sbom("{"),
		"components not an array": Sbom(`{"components":"x"}`),
	} {
		t.Run(name, func(t *testing.T) {
			graph := projGraph(node{id: "foo@1.0", name: "foo", version: "1.0"})
			want := marshalGraphs(t, []*depgraph.DepGraph{graph})
			log := &recordingLogger{}

			labelComponents(t.Context(), log, sbom, []*depgraph.DepGraph{graph}, "uv.lock")

			assert.Equal(t, want, marshalGraphs(t, []*depgraph.DepGraph{graph}))
			assert.True(t, log.contains("without component metadata"), "%v", log.messages)
		})
	}
}

// A component with no readable name or version names no node; the rest are
// labeled. The plugin rejects such an export before labeling, so the index is
// checked directly.
func TestComponentLabelIndex_ComponentWithoutIdentityIsSkipped(t *testing.T) {
	sbom := syntheticExport(
		`{"name":7,"version":"1.0"}`,
		component("foo", "1.0", dist{"https://feed.example/f/foo-1.0-py3-none-any.whl", hashA}),
	)

	index, err := componentLabelIndex(sbom)

	require.NoError(t, err)
	assert.Equal(t, artifactLabels("https://feed.example/f/foo-1.0-py3-none-any.whl", hashA), map[string]string(index["foo@1.0"]))
}
