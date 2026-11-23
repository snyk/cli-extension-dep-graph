package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	godepgraph "github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// metadataLockFile locks one crate per source kind the labels distinguish.
// "a" and "b" are workspace members; "b" also shares its name@version with a
// registry crate, which must not give the member a hash.
const metadataLockFile = `version = 4

[[package]]
name = "a"
version = "0.1.0"
dependencies = ["b", "itoa", "serde", "private", "gitdep", "pathdep", "dup"]

[[package]]
name = "b"
version = "0.1.0"

[[package]]
name = "b"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b"

[[package]]
name = "itoa"
version = "1.0.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b"

[[package]]
name = "serde"
version = "1.0.193"
source = "sparse+https://index.crates.io/"
checksum = "25dd9975e68d0cb5aa1120c288333fc98731bd1dd12f561e468ea4728c042b89"

[[package]]
name = "private"
version = "2.1.0"
source = "sparse+https://cargo.internal.example/api/index/"
checksum = "25dd9975e68d0cb5aa1120c288333fc98731bd1dd12f561e468ea4728c042b89"

[[package]]
name = "gitdep"
version = "0.2.0"
source = "git+https://github.com/example/gitdep?branch=main#0123456789abcdef"

[[package]]
name = "pathdep"
version = "0.1.0"

[[package]]
name = "dup"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "49f1f14873335454500d59611f1cf4a4b0f786f9ac11f4312a78e4cf2566695b"

[[package]]
name = "dup"
version = "1.0.0"
source = "sparse+https://cargo.internal.example/api/index/"
checksum = "25dd9975e68d0cb5aa1120c288333fc98731bd1dd12f561e468ea4728c042b89"
`

const metadataTreeA = `0a v0.1.0 (/ws/crates/a)
1b v0.1.0 (/ws/crates/b)
1itoa v1.0.11
1serde v1.0.193
1private v2.1.0
1gitdep v0.2.0 (https://github.com/example/gitdep?branch=main#01234567)
1pathdep v0.1.0 (/ws/pathdep)
1dup v1.0.0
`

const metadataTreeB = `0b v0.1.0 (/ws/crates/b)
1itoa v1.0.11
`

func metadataWorkspace(t *testing.T) (string, *fakeExecutor) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte(metadataLockFile), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))

	aManifest := filepath.Join(dir, "crates", "a", cargoTomlFile)
	bManifest := filepath.Join(dir, "crates", "b", cargoTomlFile)
	exec := &fakeExecutor{
		metadataOutput: fmt.Sprintf(`{
			"packages": [
				{"name": "a", "version": "0.1.0", "id": "id-a", "manifest_path": %q},
				{"name": "b", "version": "0.1.0", "id": "id-b", "manifest_path": %q}
			],
			"workspace_members": ["id-a", "id-b"],
			"workspace_root": %q
		}`, aManifest, bManifest, dir),
		treeByPkg: map[string]string{"a": metadataTreeA, "b": metadataTreeB},
	}
	return dir, exec
}

func nodeLabels(dg *godepgraph.DepGraph) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for _, n := range dg.Graph.Nodes {
		if n.Info != nil && len(n.Info.Labels) > 0 {
			out[n.NodeID] = n.Info.Labels
		}
	}
	return out
}

func resultsByRoot(t *testing.T, results []ecosystems.SCAResult) map[string]*godepgraph.DepGraph {
	t.Helper()
	byRoot := make(map[string]*godepgraph.DepGraph, len(results))
	for _, r := range results {
		require.NoError(t, r.Error)
		byRoot[r.DepGraph.GetRootPkg().Info.Name] = r.DepGraph
	}
	return byRoot
}

// The flag-off output must not depend on Cargo.lock's content at all: a lock
// full of checksums and an unparseable one give the same graphs.
func TestComponentMetadata_FlagOff_OutputUnchanged(t *testing.T) {
	t.Setenv("CARGO_HOME", t.TempDir())
	dir, exec := metadataWorkspace(t)

	results, err := scatest.Run(context.Background(), Plugin{executor: exec}, logger.Nop(), dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	byRoot := resultsByRoot(t, results)
	require.Len(t, byRoot, 2)
	for name, dg := range byRoot {
		for _, n := range dg.Graph.Nodes {
			assert.Nil(t, n.Info, "%s: node %s has info with the flag off", name, n.NodeID)
		}
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte("[[package]\nname = "), 0o600))
	garbage, err := scatest.Run(context.Background(), Plugin{executor: exec}, logger.Nop(), dir, &ecosystems.SCAPluginOptions{})
	require.NoError(t, err)
	for name, dg := range resultsByRoot(t, garbage) {
		assert.JSONEq(t, sortedGraphJSON(t, byRoot[name]), sortedGraphJSON(t, dg))
	}
}

func TestComponentMetadata_FlagOn_LabelsRegistryCrates(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CARGO_HOME", home)
	writeRegistryConfig(t, home, "cargo.internal.example-0123456789abcdef",
		`{"dl":"https://cargo.internal.example/api/download/{crate}/{version}/{sha256-checksum}"}`)
	dir, exec := metadataWorkspace(t)

	opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true)
	results, err := scatest.Run(context.Background(), Plugin{executor: exec}, logger.Nop(), dir, opts)
	require.NoError(t, err)

	byRoot := resultsByRoot(t, results)
	require.Len(t, byRoot, 2)

	itoa := map[string]string{
		"hash:sha-256":     itoaChecksum,
		"distribution:url": "https://static.crates.io/crates/itoa/1.0.11/download",
	}
	assert.Equal(t, map[string]map[string]string{
		"itoa@1.0.11": itoa,
		"serde@1.0.193": {
			"hash:sha-256":     serdeChecksum,
			"distribution:url": "https://static.crates.io/crates/serde/1.0.193/download",
		},
		"private@2.1.0": {
			"hash:sha-256":     serdeChecksum,
			"distribution:url": "https://cargo.internal.example/api/download/private/2.1.0/" + serdeChecksum,
		},
		// No entries for b (workspace member), gitdep, pathdep or dup
		// (two sources lock dup@1.0.0).
	}, nodeLabels(byRoot["a"]))

	assert.Equal(t, map[string]map[string]string{"itoa@1.0.11": itoa}, nodeLabels(byRoot["b"]))
}

// Under AllowOutOfSync cargo re-resolves and rewrites Cargo.lock while
// running cargo tree. The labels must come from the lock cargo used, not the
// one on disk before the scan: here regex moves from crates.io to a path dep.
func TestComponentMetadata_FlagOn_ReadsLockAfterCargoRewritesIt(t *testing.T) {
	t.Setenv("CARGO_HOME", t.TempDir())
	dir := t.TempDir()
	lockPath := filepath.Join(dir, cargoLockFile)
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoTomlFile), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(lockPath, []byte(`version = 4

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "regex"
version = "1.11.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b544ef1b4eac5dc2db33ea63606ae9ffcfac26c1416a2806ae0bf5f56b201191"
`), 0o600))

	exec := &fakeExecutor{
		metadataOutput: singleCrateMetadata(dir),
		treeByPkg:      map[string]string{"my-app": "0my-app v0.1.0\n1regex v1.11.1 (/local/regex)\n"},
		beforeTree: func() {
			require.NoError(t, os.WriteFile(lockPath, []byte(`version = 4

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "regex"
version = "1.11.1"
`), 0o600))
		},
	}

	opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true).WithAllowOutOfSync(true)
	results, err := scatest.Run(context.Background(), Plugin{executor: exec}, logger.Nop(), dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NoError(t, results[0].Error)
	assert.Empty(t, nodeLabels(results[0].DepGraph), "regex is a path crate in the lock cargo used")
}

func bufferLogger() (logger.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return logger.NewFromSlog(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))), &buf
}

// Cargo.lock is parsed only once cargo tree has accepted it. cargo metadata
// --no-deps does not read the lock, so without this ordering a crafted lock
// that cargo rejects would still reach the TOML parser.
func TestComponentMetadata_FlagOn_LockNotParsedWhenCargoTreeFails(t *testing.T) {
	t.Setenv("CARGO_HOME", t.TempDir())
	dir, exec := metadataWorkspace(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, cargoLockFile), []byte("[[package]\nname = "), 0o600))
	exec.treeErrByPkg = map[string]error{"a": errors.New("lock rejected"), "b": errors.New("lock rejected")}

	log, buf := bufferLogger()
	opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true)
	results, err := scatest.Run(context.Background(), Plugin{executor: exec}, log, dir, opts)
	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, r := range results {
		require.Error(t, r.Error)
	}
	assert.NotContains(t, buf.String(), "component", "Cargo.lock must not be parsed")
}

func TestComponentMetadata_FlagOn_UnusableLockFileStillScans(t *testing.T) {
	tests := []struct {
		name  string
		write func(t *testing.T, path string)
	}{
		{"malformed", func(t *testing.T, path string) {
			t.Helper()
			require.NoError(t, os.WriteFile(path, []byte("[[package]\nname = "), 0o600))
		}},
		{"over the size cap", func(t *testing.T, path string) {
			t.Helper()
			// A valid lock whose first entry would be labeled, padded past
			// the cap with a TOML comment.
			head := "version = 4\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.11\"\n" +
				"source = \"registry+https://github.com/rust-lang/crates.io-index\"\n" +
				"checksum = \"" + itoaChecksum + "\"\n#"
			data := append([]byte(head), bytes.Repeat([]byte("x"), maxLockFileSize-len(head)+1)...)
			require.NoError(t, os.WriteFile(path, data, 0o600))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CARGO_HOME", t.TempDir())
			dir, exec := metadataWorkspace(t)
			tt.write(t, filepath.Join(dir, cargoLockFile))

			log, buf := bufferLogger()
			opts := ecosystems.NewPluginOptions().WithIncludeComponentMetadata(true)
			results, err := scatest.Run(context.Background(), Plugin{executor: exec}, log, dir, opts)
			require.NoError(t, err)

			byRoot := resultsByRoot(t, results)
			require.Len(t, byRoot, 2)
			assert.Len(t, byRoot["a"].Pkgs, 8, "the graph is built as without the flag")
			for _, dg := range byRoot {
				assert.Empty(t, nodeLabels(dg))
			}
			assert.Contains(t, buf.String(), "no component hashes emitted")
			assert.Contains(t, buf.String(), cargoLockFile)
		})
	}
}

func sortedGraphJSON(t *testing.T, dg *godepgraph.DepGraph) string {
	t.Helper()
	type node struct {
		PkgID string               `json:"pkgId"`
		Info  *godepgraph.NodeInfo `json:"info"`
		Deps  []string             `json:"deps"`
	}
	nodes := make(map[string]node, len(dg.Graph.Nodes))
	for _, n := range dg.Graph.Nodes {
		deps := make([]string, 0, len(n.Deps))
		for _, d := range n.Deps {
			deps = append(deps, d.NodeID)
		}
		sort.Strings(deps)
		nodes[n.NodeID] = node{PkgID: n.PkgID, Info: n.Info, Deps: deps}
	}
	pkgs := make(map[string]godepgraph.PkgInfo, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		pkgs[p.ID] = p.Info
	}
	data, err := json.Marshal(map[string]any{"nodes": nodes, "pkgs": pkgs})
	require.NoError(t, err)
	return string(data)
}
