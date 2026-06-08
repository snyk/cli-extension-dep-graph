package remoteconv

import (
	"testing"

	"github.com/snyk/dep-graph/go/pkg/depgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/snykclient"
)

func TestExtractDepGraphsFromScans_Success(t *testing.T) {
	depGraph1 := createTestDepGraph("package1", "1.0.0")
	depGraph2 := createTestDepGraph("package2", "2.0.0")

	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: depGraph1},
			},
		},
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: depGraph2},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	require.Len(t, depGraphs, 2)
	assert.Equal(t, "package1", depGraphs[0].GetRootPkg().Info.Name)
	assert.Equal(t, "package2", depGraphs[1].GetRootPkg().Info.Name)
}

func TestExtractDepGraphsFromScans_MultipleFactsInSingleScan(t *testing.T) {
	depGraph1 := createTestDepGraph("package1", "1.0.0")
	depGraph2 := createTestDepGraph("package2", "2.0.0")

	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: depGraph1},
				{Type: "depGraph", Data: depGraph2},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	require.Len(t, depGraphs, 2)
	assert.Equal(t, "package1", depGraphs[0].GetRootPkg().Info.Name)
	assert.Equal(t, "package2", depGraphs[1].GetRootPkg().Info.Name)
}

func TestExtractDepGraphsFromScans_WrongFactType(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "otherType", Data: "some data"},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0) // Wrong fact types are skipped
}

func TestExtractDepGraphsFromScans_MixedFactTypes(t *testing.T) {
	depGraph1 := createTestDepGraph("package1", "1.0.0")

	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "otherType", Data: "some data"},
				{Type: "depGraph", Data: depGraph1},
				{Type: "anotherType", Data: 123},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	require.Len(t, depGraphs, 1)
	assert.Equal(t, "package1", depGraphs[0].GetRootPkg().Info.Name)
}

func TestExtractDepGraphsFromScans_TypeAssertionFailure(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: "not a depGraph"}, // Wrong type
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	assert.Error(t, err)
	assert.Nil(t, depGraphs)
	assert.Contains(t, err.Error(), "expected fact.Data to be *depgraph.DepGraph")
}

func TestExtractDepGraphsFromScans_NilDepGraph(t *testing.T) {
	var nilDepGraph *depgraph.DepGraph
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "depGraph", Data: nilDepGraph},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	assert.Error(t, err)
	assert.Nil(t, depGraphs)
	assert.Contains(t, err.Error(), "depGraph is nil")
}

func TestExtractDepGraphsFromScans_NoDepGraphFacts(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{
				{Type: "fact1", Data: "data1"},
				{Type: "fact2", Data: "data2"},
			},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func TestExtractDepGraphsFromScans_EmptyScans(t *testing.T) {
	scans := []*snykclient.ScanResult{}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func TestExtractDepGraphsFromScans_NilScans(t *testing.T) {
	var scans []*snykclient.ScanResult

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func TestExtractDepGraphsFromScans_ScanWithNoFacts(t *testing.T) {
	scans := []*snykclient.ScanResult{
		{
			Facts: []*snykclient.ScanResultFact{},
		},
	}

	depGraphs, err := extractDepGraphsFromScans(scans)

	require.NoError(t, err)
	assert.Len(t, depGraphs, 0)
}

func createTestDepGraph(name, version string) *depgraph.DepGraph {
	builder, err := depgraph.NewBuilder(
		&depgraph.PkgManager{Name: "uv"},
		&depgraph.PkgInfo{Name: name, Version: version},
	)
	if err != nil {
		panic(err)
	}
	return builder.Build()
}
