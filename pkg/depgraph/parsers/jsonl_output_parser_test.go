package parsers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONLOutputParser_ParseOutput(t *testing.T) {
	parser := NewJSONL()

	input := []byte(`{"depGraph":{"arbitraryJsonKey":"first value"},"normalisedTargetFile":"package-lock.json","targetFileFromPlugin":"target-from-plugin","target":{"key":"value"}}
{"depGraph":{"arbitraryJsonKey":"second value"},"normalisedTargetFile":"pom.xml"}`)

	results, err := parser.ParseOutput(input)

	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "package-lock.json", results[0].NormalisedTargetFile)
	require.NotNil(t, results[0].TargetFileFromPlugin)
	assert.Equal(t, "target-from-plugin", *results[0].TargetFileFromPlugin)
	require.NotNil(t, results[0].Target)
	assert.Equal(t, `{"key":"value"}`, string(results[0].Target))
	assert.Equal(t, `{"arbitraryJsonKey":"first value"}`, string(results[0].DepGraph))

	assert.Equal(t, "pom.xml", results[1].NormalisedTargetFile)
	assert.Equal(t, string(results[1].DepGraph), `{"arbitraryJsonKey":"second value"}`)
	assert.Nil(t, results[1].TargetFileFromPlugin)
	assert.Nil(t, results[1].Target)
}

func TestJSONLOutputParser_ParseOutput_BlankOutput(t *testing.T) {
	parser := NewJSONL()

	input := []byte(" \n")

	results, err := parser.ParseOutput(input)

	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestJSONLOutputParser_ParseOutput_InvalidJSON(t *testing.T) {
	parser := NewJSONL()

	input := []byte(`{"depGraph":{"invalid json},"normalisedTargetFile":"test"}`)

	results, err := parser.ParseOutput(input)

	require.Error(t, err)
	assert.Nil(t, results)
}
