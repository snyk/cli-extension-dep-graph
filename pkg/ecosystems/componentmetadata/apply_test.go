package componentmetadata_test

import (
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/componentmetadata"
)

func TestLabels_ApplyTo(t *testing.T) {
	t.Run("creates NodeInfo on a bare node", func(t *testing.T) {
		node := &depgraph.Node{NodeID: "a@1"}
		componentmetadata.Labels{"hash:sha-256": "ab"}.ApplyTo(node)
		assert.Equal(t, &depgraph.NodeInfo{Labels: map[string]string{"hash:sha-256": "ab"}}, node.Info)
	})

	t.Run("keeps existing labels and other NodeInfo fields", func(t *testing.T) {
		prov := &depgraph.VersionProvenance{Type: "x"}
		node := &depgraph.Node{Info: &depgraph.NodeInfo{VersionProvenance: prov, Labels: map[string]string{"pruned": "true"}}}
		componentmetadata.Labels{"hash:sha-256": "ab"}.ApplyTo(node)
		assert.Equal(t, map[string]string{"pruned": "true", "hash:sha-256": "ab"}, node.Info.Labels)
		assert.Same(t, prov, node.Info.VersionProvenance)
	})

	t.Run("an existing label wins over a component-metadata label", func(t *testing.T) {
		node := &depgraph.Node{Info: &depgraph.NodeInfo{Labels: map[string]string{"hash:sha-256": "original"}}}
		componentmetadata.Labels{"hash:sha-256": "new"}.ApplyTo(node)
		assert.Equal(t, "original", node.Info.Labels["hash:sha-256"])
	})

	t.Run("empty labels leave the node untouched", func(t *testing.T) {
		node := &depgraph.Node{}
		componentmetadata.Labels{}.ApplyTo(node)
		assert.Nil(t, node.Info)
	})

	t.Run("does not alias the Labels map into the node", func(t *testing.T) {
		l := componentmetadata.Labels{"hash:sha-256": "ab"}
		node := &depgraph.Node{}
		l.ApplyTo(node)
		l["distribution:url"] = "https://h/x"
		assert.NotContains(t, node.Info.Labels, "distribution:url")
	})
}
