//go:build !integration
// +build !integration

package pip

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

var (
	sha256Hex = strings.Repeat("ab", 32)
	md5Hex    = strings.Repeat("cd", 16)
)

// reportJSON is shaped like pip's installation report (format version 1):
// each install item carries download_info for the exact archive pip picked.
// https://pip.pypa.io/en/stable/reference/installation-report/
func reportJSON(downloadInfos ...string) string {
	items := make([]string, len(downloadInfos))
	for i, di := range downloadInfos {
		name := []string{"alpha", "beta", "gamma", "delta"}[i]
		item := `{"metadata":{"name":"` + name + `","version":"1.0"},"requested":true`
		if di != "" {
			item += `,"download_info":` + di
		}
		items[i] = item + "}"
	}
	return `{"version":"1","install":[` + strings.Join(items, ",") + `]}`
}

func labelsByNode(t *testing.T, raw string, opts ...GraphOption) map[string]map[string]string {
	t.Helper()
	var report Report
	require.NoError(t, json.Unmarshal([]byte(raw), &report))
	g, err := report.ToDependencyGraph(t.Context(), logger.Nop(), "proj", opts...)
	require.NoError(t, err)
	out := map[string]map[string]string{}
	for _, n := range g.Graph.Nodes {
		if n.Info != nil && len(n.Info.Labels) > 0 {
			out[n.NodeID] = n.Info.Labels
		}
	}
	return out
}

func TestReport_ComponentMetadata(t *testing.T) {
	t.Run("labels every hash in the hashes map and the archive URL", func(t *testing.T) {
		raw := reportJSON(`{"url":"https://files.example/alpha-1.0-py3-none-any.whl",` +
			`"archive_info":{"hash":"sha256=` + sha256Hex + `","hashes":{"sha256":"` + sha256Hex + `","md5":"` + md5Hex + `"}}}`)
		assert.Equal(t, map[string]map[string]string{
			"alpha@1.0": {
				"hash:sha-256":     sha256Hex,
				"hash:md5":         md5Hex,
				"distribution:url": "https://files.example/alpha-1.0-py3-none-any.whl",
			},
		}, labelsByNode(t, raw, WithComponentMetadata()))
	})

	t.Run("falls back to the legacy hash field before pip 23.0", func(t *testing.T) {
		raw := reportJSON(`{"url":"https://files.example/alpha-1.0.tar.gz","archive_info":{"hash":"sha256=` + sha256Hex + `"}}`)
		assert.Equal(t, map[string]map[string]string{
			"alpha@1.0": {"hash:sha-256": sha256Hex, "distribution:url": "https://files.example/alpha-1.0.tar.gz"},
		}, labelsByNode(t, raw, WithComponentMetadata()))
	})

	t.Run("skips a malformed legacy hash but keeps the URL", func(t *testing.T) {
		raw := reportJSON(`{"url":"https://files.example/a.whl","archive_info":{"hash":"` + sha256Hex + `"}}`)
		assert.Equal(t, map[string]map[string]string{
			"alpha@1.0": {"distribution:url": "https://files.example/a.whl"},
		}, labelsByNode(t, raw, WithComponentMetadata()))
	})

	t.Run("strips credentials, query and fragment from the URL", func(t *testing.T) {
		raw := reportJSON(`{"url":"https://u:p@feed.example/simple/alpha/alpha-1.0.whl?x=1#sha256=` + sha256Hex + `",` +
			`"archive_info":{"hashes":{"sha256":"` + sha256Hex + `"}}}`)
		assert.Equal(t, map[string]map[string]string{
			"alpha@1.0": {"hash:sha-256": sha256Hex, "distribution:url": "https://feed.example/simple/alpha/alpha-1.0.whl"},
		}, labelsByNode(t, raw, WithComponentMetadata()))
	})

	t.Run("VCS, local directory and unreported installs get no labels; a local archive keeps its hash", func(t *testing.T) {
		raw := reportJSON(
			`{"url":"https://github.com/org/alpha","vcs_info":{"vcs":"git","commit_id":"`+strings.Repeat("1", 40)+`"}}`,
			`{"url":"file:///src/beta","dir_info":{"editable":true}}`,
			`{"url":"file:///wheels/gamma-1.0.whl","archive_info":{"hashes":{"sha256":"`+sha256Hex+`"}}}`,
			``,
		)
		assert.Equal(t, map[string]map[string]string{
			"gamma@1.0": {"hash:sha-256": sha256Hex},
		}, labelsByNode(t, raw, WithComponentMetadata()))
	})

	t.Run("without the option no node is labelled", func(t *testing.T) {
		raw := reportJSON(`{"url":"https://files.example/a.whl","archive_info":{"hashes":{"sha256":"` + sha256Hex + `"}}}`)
		assert.Empty(t, labelsByNode(t, raw))
	})

	// sbom-export folds a :pruned stub into its full node, as for nuget and
	// snyk-mvn-plugin, so the stub carries only its pruned label.
	t.Run("a pruned stub keeps only its pruned label", func(t *testing.T) {
		raw := `{"install":[` +
			`{"metadata":{"name":"a","version":"1","requires_dist":["b"]},"requested":true,` +
			`"download_info":{"url":"https://h/a.whl","archive_info":{"hashes":{"sha256":"` + sha256Hex + `"}}}},` +
			`{"metadata":{"name":"b","version":"1","requires_dist":["a"]}}]}`
		got := labelsByNode(t, raw, WithComponentMetadata())
		assert.Equal(t, map[string]string{"pruned": "true"}, got["a@1:pruned"])
		assert.Equal(t, map[string]string{"hash:sha-256": sha256Hex, "distribution:url": "https://h/a.whl"}, got["a@1"])
	})
}
