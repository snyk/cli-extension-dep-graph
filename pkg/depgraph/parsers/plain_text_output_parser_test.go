package parsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlainTextOutputParser_ParseOutput(t *testing.T) {
	parser := NewPlainText()

	input := []byte(`DepGraph data:
{
  "schemaVersion": "1.2.0",
  "pkgManager": {
    "name": "npm"
  },
  "pkgs": [
    {
      "id": "app1@1.0.0",
      "info": {
        "name": "app1",
        "version": "1.0.0"
      }
    }
  ],
  "graph": {
    "rootNodeId": "root-node",
    "nodes": [
      {
        "nodeId": "root-node",
        "pkgId": "app1@1.0.0",
        "deps": []
      }
    ]
  }
}
DepGraph target:
package-lock.json
DepGraph end
DepGraph data:
{
  "schemaVersion": "1.2.0",
  "pkgManager": {
    "name": "maven"
  },
  "pkgs": [
    {
      "id": "com.example:app2@2.0.0",
      "info": {
        "name": "com.example:app2",
        "version": "2.0.0"
      }
    }
  ],
  "graph": {
    "rootNodeId": "root-node",
    "nodes": [
      {
        "nodeId": "root-node",
        "pkgId": "com.example:app2@2.0.0",
        "deps": []
      }
    ]
  }
}
DepGraph target:
pom.xml
DepGraph end`)

	results, err := parser.ParseOutput(input)

	require.NoError(t, err)
	require.Len(t, results, 2)

	// First depgraph
	assert.Equal(t, "package-lock.json", results[0].DisplayTargetName)
	assert.Contains(t, string(results[0].DepGraph), `"name": "npm"`)
	assert.Contains(t, string(results[0].DepGraph), `"app1@1.0.0"`)

	// Second depgraph
	assert.Equal(t, "pom.xml", results[1].DisplayTargetName)
	assert.Contains(t, string(results[1].DepGraph), `"name": "maven"`)
	assert.Contains(t, string(results[1].DepGraph), `"com.example:app2@2.0.0"`)
}

func TestPlainTextOutputParser_ParseOutput_BlankOutput(t *testing.T) {
	parser := NewPlainText()

	input := []byte(" \n")

	results, err := parser.ParseOutput(input)

	require.NoError(t, err)
	assert.Empty(t, results)
}
