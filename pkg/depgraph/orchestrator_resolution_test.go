package depgraph

import (
	"errors"
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

func TestOrchestratorResultToWorkflowData_Success(t *testing.T) {
	dg := &depgraph.DepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    depgraph.PkgManager{Name: "npm"},
		Pkgs: []depgraph.Pkg{
			{ID: "proj@1.0.0", Info: depgraph.PkgInfo{Name: "proj", Version: "1.0.0"}},
		},
		Graph: depgraph.Graph{RootNodeID: "root"},
	}
	targetFile := "package.json"

	result := &ecosystems.SCAResult{
		DepGraph: dg,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: &targetFile,
			},
		},
	}

	data, err := orchestratorResultToWorkflowData(result)

	require.NoError(t, err)
	require.NotNil(t, data)

	payload, ok := data.GetPayload().([]byte)
	require.True(t, ok)
	assert.Contains(t, string(payload), "npm")

	normalisedTargetFile, err := data.GetMetaData(workflow.MetaKeyNormalisedTargetFile)
	require.NoError(t, err)
	assert.Equal(t, "package.json", normalisedTargetFile)

	targetFileFromPlugin, err := data.GetMetaData(workflow.MetaKeyTargetFileFromPlugin)
	require.NoError(t, err)
	assert.Equal(t, "package.json", targetFileFromPlugin)
}

func TestOrchestratorResultToWorkflowData_NilTargetFile(t *testing.T) {
	dg := &depgraph.DepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    depgraph.PkgManager{Name: "maven"},
	}

	result := &ecosystems.SCAResult{
		DepGraph: dg,
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: nil,
			},
		},
	}

	data, err := orchestratorResultToWorkflowData(result)

	require.NoError(t, err)
	require.NotNil(t, data)

	normalisedTargetFile, err := data.GetMetaData(workflow.MetaKeyNormalisedTargetFile)
	require.NoError(t, err)
	assert.Equal(t, "", normalisedTargetFile)
}

func TestOrchestratorResultToWorkflowData_ResultError(t *testing.T) {
	targetFile := "pom.xml"
	result := &ecosystems.SCAResult{
		ProjectDescriptor: identity.ProjectDescriptor{
			Identity: identity.ProjectIdentity{
				TargetFile: &targetFile,
			},
		},
		Error: errors.New("resolution failed"),
	}

	_, err := orchestratorResultToWorkflowData(result)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve depgraph for pom.xml")
	assert.ErrorContains(t, err, "resolution failed")
}
