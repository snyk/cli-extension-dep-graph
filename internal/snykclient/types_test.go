package snykclient

import (
	"encoding/json"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/internal/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanResultFact_UnmarshalJSON_DepGraph(t *testing.T) {
	jsonData := `{
		"type": "depGraph",
		"data": {
			"schemaVersion": "1.2.0",
			"pkgManager": {
				"name": "npm",
				"version": "8.0.0",
				"repositories": [
					{
						"alias": "npmjs"
					}
				]
			},
			"pkgs": [
				{
					"id": "root@1.0.0",
					"info": {
						"name": "root",
						"version": "1.0.0",
						"purl": "pkg:npm/root@1.0.0"
					}
				},
				{
					"id": "dep@2.0.0",
					"info": {
						"name": "dep",
						"version": "2.0.0"
					}
				}
			],
			"graph": {
				"rootNodeId": "root-node",
				"nodes": [
					{
						"nodeId": "root-node",
						"pkgId": "root@1.0.0",
						"deps": [
							{
								"nodeId": "dep-node"
							}
						]
					},
					{
						"nodeId": "dep-node",
						"pkgId": "dep@2.0.0",
						"deps": []
					}
				]
			}
		}
	}`

	var fact ScanResultFact
	err := json.Unmarshal([]byte(jsonData), &fact)

	require.NoError(t, err)
	assert.Equal(t, "depGraph", fact.Type)

	depGraph, ok := fact.Data.(*depgraph.DepGraph)
	require.True(t, ok, "expected fact.Data to be *depgraph.DepGraph")
	require.NotNil(t, depGraph)

	assert.Equal(t, "1.2.0", depGraph.SchemaVersion)
	assert.Equal(t, "npm", depGraph.PkgManager.Name)
	assert.Equal(t, "8.0.0", depGraph.PkgManager.Version)
	assert.Len(t, depGraph.PkgManager.Repositories, 1)
	assert.Equal(t, "npmjs", depGraph.PkgManager.Repositories[0].Alias)

	require.Len(t, depGraph.Pkgs, 2)
	assert.Equal(t, "root@1.0.0", depGraph.Pkgs[0].ID)
	assert.Equal(t, "root", depGraph.Pkgs[0].Info.Name)
	assert.Equal(t, "1.0.0", depGraph.Pkgs[0].Info.Version)
	assert.Equal(t, "pkg:npm/root@1.0.0", depGraph.Pkgs[0].Info.PackageURL)
	assert.Equal(t, "dep@2.0.0", depGraph.Pkgs[1].ID)

	assert.Equal(t, "root-node", depGraph.Graph.RootNodeID)
	require.Len(t, depGraph.Graph.Nodes, 2)
	assert.Equal(t, "root-node", depGraph.Graph.Nodes[0].NodeID)
	assert.Equal(t, "root@1.0.0", depGraph.Graph.Nodes[0].PkgID)
	require.Len(t, depGraph.Graph.Nodes[0].Deps, 1)
	assert.Equal(t, "dep-node", depGraph.Graph.Nodes[0].Deps[0].NodeID)
	assert.Equal(t, "dep-node", depGraph.Graph.Nodes[1].NodeID)
	assert.Empty(t, depGraph.Graph.Nodes[1].Deps)
}

func TestScanResultFact_UnmarshalJSON_OtherType(t *testing.T) {
	jsonData := `{
		"type": "vulnerability",
		"data": {
			"severity": "high",
			"title": "Test vulnerability"
		}
	}`

	var fact ScanResultFact
	err := json.Unmarshal([]byte(jsonData), &fact)

	require.NoError(t, err)
	assert.Equal(t, "vulnerability", fact.Type)

	dataMap, ok := fact.Data.(map[string]any)
	require.True(t, ok, "expected fact.Data to be map[string]any")
	assert.Equal(t, "high", dataMap["severity"])
	assert.Equal(t, "Test vulnerability", dataMap["title"])
}

func TestScanResultFact_UnmarshalJSON_MalformedDepGraph(t *testing.T) {
	jsonData := `{
		"type": "depGraph",
		"data": {
			"schemaVersion": "1.2.0",
			"pkgs": "this should be an array not a string"
		}
	}`

	var fact ScanResultFact
	err := json.Unmarshal([]byte(jsonData), &fact)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal depGraph data")
}

func TestScanResultFact_UnmarshalJSON_MissingDataField(t *testing.T) {
	tests := []struct {
		name           string
		jsonData       string
		expectedErrMsg string
	}{
		{
			name: "missing data field for depGraph",
			jsonData: `{
				"type": "depGraph"
			}`,
			expectedErrMsg: "failed to unmarshal depGraph data",
		},
		{
			name: "missing data field for other type",
			jsonData: `{
				"type": "vulnerability"
			}`,
			expectedErrMsg: "failed to unmarshal fact data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fact ScanResultFact
			err := json.Unmarshal([]byte(tt.jsonData), &fact)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrMsg)
		})
	}
}
