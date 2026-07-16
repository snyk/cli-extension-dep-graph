//go:build integration && gradle
// +build integration,gradle

package gradle

import (
	"context"
	"encoding/hex"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/scatest"
)

// componentMetadataHashLabels maps each digest label the init script must emit
// for every resolved external artifact under --include-component-metadata to
// its expected lowercase-hex length.
var componentMetadataHashLabels = map[string]int{
	"hash:md5":     32,  // 16 bytes
	"hash:sha-1":   40,  // 20 bytes
	"hash:sha-256": 64,  // 32 bytes
	"hash:sha-512": 128, // 64 bytes
}

// TestPlugin_ComponentMetadataIntegration exercises --include-component-metadata
// end-to-end against a real Gradle build. Hashes are deterministic (computed
// from the resolved artifact files), so they are asserted strictly. The
// distribution:url label depends on the resource-read listener firing during
// this run — the feature degrades gracefully when Gradle's internal API is
// unavailable or the cache is warm — so its presence is best-effort, but its
// shape (no credentials/query/fragment) is asserted strictly whenever present.
func TestPlugin_ComponentMetadataIntegration(t *testing.T) {
	gradleVersion, err := gradleRuntime()
	require.NoErrorf(t, err, "could not detect gradle runtime version")
	jdkVersion, err := jdkRuntime()
	require.NoErrorf(t, err, "could not detect jdk runtime version")
	t.Logf("gradle %s / jdk %s", gradleVersion, jdkVersion)

	fixtureDir := filepath.Join(fixturesRoot, "simple")
	absFixture, err := filepath.Abs(fixtureDir)
	require.NoError(t, err, "failed to resolve simple fixture path")

	t.Run("hashes_and_clean_distribution_url_when_enabled", func(t *testing.T) {
		// A cold Gradle cache guarantees the artifacts are downloaded during
		// this run, so the resource-read listener fires and distribution:url is
		// populated. cmd.Env is inherited by the gradle subprocess (executor.go
		// leaves cmd.Env nil), so GRADLE_USER_HOME propagates.
		t.Setenv("GRADLE_USER_HOME", t.TempDir())

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		plugin := NewGradlePlugin()
		results, err := scatest.Run(ctx, plugin, logger.Nop(), absFixture,
			ecosystems.NewPluginOptions().
				WithIncludeComponentMetadata(true).
				WithGradleRefreshDependencies(true))
		require.NoError(t, err, "BuildDepGraphsFromDir should not return error")
		require.NotEmpty(t, results, "plugin must emit at least one result")

		nodes := nodesWithComponentMetadata(results)
		require.NotEmpty(t, nodes,
			"expected at least one resolved external node to carry hash labels")

		var sawDistributionURL bool
		for _, n := range nodes {
			for label, hexLen := range componentMetadataHashLabels {
				val, ok := n.Info.Labels[label]
				require.Truef(t, ok, "node %s is missing the %s label", n.NodeID, label)
				assertLowercaseHex(t, n.NodeID, label, val, hexLen)
			}
			if durl, ok := n.Info.Labels["distribution:url"]; ok {
				sawDistributionURL = true
				assertCleanDistributionURL(t, n.NodeID, durl)
			}
		}

		if !sawDistributionURL {
			// Not a failure: distribution:url is best-effort and depends on the
			// internal build-operation listener being available on this Gradle
			// version. Surface it so a silent loss of coverage is visible.
			t.Logf("no distribution:url labels were captured on gradle %s; "+
				"hash coverage was still asserted", gradleVersion)
		}
	})

	t.Run("no_component_metadata_labels_when_disabled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		plugin := NewGradlePlugin()
		results, err := scatest.Run(ctx, plugin, logger.Nop(), absFixture,
			ecosystems.NewPluginOptions())
		require.NoError(t, err, "BuildDepGraphsFromDir should not return error")
		require.NotEmpty(t, results, "plugin must emit at least one result")

		for _, r := range results {
			if r.DepGraph == nil {
				continue
			}
			for _, n := range r.DepGraph.Graph.Nodes {
				if n.Info == nil {
					continue
				}
				for label := range n.Info.Labels {
					assert.Falsef(t,
						strings.HasPrefix(label, "hash:") || label == "distribution:url",
						"node %s should not carry component-metadata label %q when the flag is off",
						n.NodeID, label)
				}
			}
		}
	})
}

// nodesWithComponentMetadata returns the graph nodes that carry component
// metadata, identified by the presence of a hash:sha-256 label (emitted only
// for resolved external artifacts).
func nodesWithComponentMetadata(results []ecosystems.SCAResult) []depgraph.Node {
	var out []depgraph.Node
	for _, r := range results {
		if r.DepGraph == nil {
			continue
		}
		for _, n := range r.DepGraph.Graph.Nodes {
			if n.Info != nil {
				if _, ok := n.Info.Labels["hash:sha-256"]; ok {
					out = append(out, n)
				}
			}
		}
	}
	return out
}

func assertLowercaseHex(t *testing.T, nodeID, label, val string, wantLen int) {
	t.Helper()
	assert.Lenf(t, val, wantLen, "node %s label %s: unexpected hex length", nodeID, label)
	assert.Equalf(t, strings.ToLower(val), val,
		"node %s label %s: expected lowercase hex, got %q", nodeID, label, val)
	_, err := hex.DecodeString(val)
	assert.NoErrorf(t, err, "node %s label %s: value %q is not valid hex", nodeID, label, val)
}

// assertCleanDistributionURL enforces the credential-safety contract: the label
// must be an http(s) URL reduced to its canonical location, with no userinfo,
// query string or fragment — the places URL-borne auth (SAS tokens, signed-URL
// signatures, basic-auth credentials) would otherwise leak from.
func assertCleanDistributionURL(t *testing.T, nodeID, durl string) {
	t.Helper()
	assert.Truef(t, strings.HasPrefix(durl, "https://") || strings.HasPrefix(durl, "http://"),
		"node %s distribution:url should be an http(s) URL: %q", nodeID, durl)
	assert.NotContainsf(t, durl, "?",
		"node %s distribution:url must not carry a query string: %q", nodeID, durl)
	assert.NotContainsf(t, durl, "#",
		"node %s distribution:url must not carry a fragment: %q", nodeID, durl)
	u, err := url.Parse(durl)
	require.NoErrorf(t, err, "node %s distribution:url is not parseable: %q", nodeID, durl)
	assert.Nilf(t, u.User,
		"node %s distribution:url must not carry userinfo: %q", nodeID, durl)
	assert.Emptyf(t, u.RawQuery,
		"node %s distribution:url must not carry a query: %q", nodeID, durl)
}
