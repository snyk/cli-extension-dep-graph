package cargo

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMetadata_SingleCrate(t *testing.T) {
	input := `{
		"packages": [
			{
				"name": "my-app",
				"version": "0.1.0",
				"id": "path+file:///abs/path#my-app@0.1.0",
				"manifest_path": "/abs/path/Cargo.toml"
			}
		],
		"workspace_members": ["path+file:///abs/path#my-app@0.1.0"],
		"workspace_root": "/abs/path"
	}`

	m, err := parseMetadata(strings.NewReader(input))
	require.NoError(t, err)

	members := m.members()
	require.Len(t, members, 1)
	assert.Equal(t, "my-app", members[0].Name)
	assert.Equal(t, "0.1.0", members[0].Version)
	assert.Equal(t, "/abs/path/Cargo.toml", members[0].ManifestPath)
}

func TestParseMetadata_MultiMemberWorkspace(t *testing.T) {
	input := `{
		"packages": [
			{
				"name": "a",
				"version": "0.1.0",
				"id": "path+file:///abs/path/a#a@0.1.0",
				"manifest_path": "/abs/path/a/Cargo.toml"
			},
			{
				"name": "b",
				"version": "0.2.0",
				"id": "path+file:///abs/path/b#b@0.2.0",
				"manifest_path": "/abs/path/b/Cargo.toml"
			}
		],
		"workspace_members": [
			"path+file:///abs/path/a#a@0.1.0",
			"path+file:///abs/path/b#b@0.2.0"
		],
		"workspace_root": "/abs/path"
	}`

	m, err := parseMetadata(strings.NewReader(input))
	require.NoError(t, err)

	members := m.members()
	require.Len(t, members, 2)
	// Order matches WorkspaceMembers ordering.
	assert.Equal(t, "a", members[0].Name)
	assert.Equal(t, "/abs/path/a/Cargo.toml", members[0].ManifestPath)
	assert.Equal(t, "b", members[1].Name)
	assert.Equal(t, "/abs/path/b/Cargo.toml", members[1].ManifestPath)
}

func TestParseMetadata_VirtualWorkspace(t *testing.T) {
	// Virtual workspace: workspace_root has no root [package], only
	// [workspace]. cargo metadata still returns the members.
	input := `{
		"packages": [
			{
				"name": "lib-a",
				"version": "0.1.0",
				"id": "path+file:///abs/path/crates/a#lib-a@0.1.0",
				"manifest_path": "/abs/path/crates/a/Cargo.toml"
			}
		],
		"workspace_members": ["path+file:///abs/path/crates/a#lib-a@0.1.0"],
		"workspace_root": "/abs/path"
	}`

	m, err := parseMetadata(strings.NewReader(input))
	require.NoError(t, err)

	members := m.members()
	require.Len(t, members, 1)
	assert.Equal(t, "lib-a", members[0].Name)
}

func TestParseMetadata_FiltersNonMemberPackages(t *testing.T) {
	// Some cargo versions emit referenced path-deps in Packages even with
	// --no-deps. Members helper must filter to WorkspaceMembers only.
	input := `{
		"packages": [
			{
				"name": "a",
				"version": "0.1.0",
				"id": "path+file:///abs/path/a#a@0.1.0",
				"manifest_path": "/abs/path/a/Cargo.toml"
			},
			{
				"name": "not-a-member",
				"version": "9.9.9",
				"id": "path+file:///elsewhere#not-a-member@9.9.9",
				"manifest_path": "/elsewhere/Cargo.toml"
			}
		],
		"workspace_members": ["path+file:///abs/path/a#a@0.1.0"],
		"workspace_root": "/abs/path"
	}`

	m, err := parseMetadata(strings.NewReader(input))
	require.NoError(t, err)

	members := m.members()
	require.Len(t, members, 1)
	assert.Equal(t, "a", members[0].Name)
}

func TestParseMetadata_MalformedJSON(t *testing.T) {
	_, err := parseMetadata(strings.NewReader("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding cargo metadata JSON")
}
