package cargo

import (
	"encoding/json"
	"fmt"
	"io"
)

// cargoMetadata is the subset of `cargo metadata --no-deps` JSON we need to
// drive workspace handling. Fields outside member enumeration (resolve,
// target_directory, etc.) are deliberately omitted.
//
// JSON field names are dictated by cargo's stable output format (snake_case),
// not by Snyk's Go conventions; tagliatelle is disabled for the relevant
// fields.
type cargoMetadata struct {
	Packages         []cargoMetadataPackage `json:"packages"`
	WorkspaceMembers []string               `json:"workspace_members"` //nolint:tagliatelle // cargo metadata output schema
	WorkspaceRoot    string                 `json:"workspace_root"`    //nolint:tagliatelle // cargo metadata output schema
}

// cargoMetadataPackage is one entry in cargoMetadata.Packages. With --no-deps,
// the array contains exactly the workspace members (plus their referenced
// path/git deps in some cargo versions, which we filter via WorkspaceMembers).
type cargoMetadataPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	ID           string `json:"id"`
	ManifestPath string `json:"manifest_path"` //nolint:tagliatelle // cargo metadata output schema
}

// workspaceMember is the trimmed view of a workspace member used by the
// plugin orchestration code.
type workspaceMember struct {
	Name string
	// Version is the resolved version from the member's Cargo.toml.
	Version string
	// ManifestPath is the absolute path to the member's Cargo.toml.
	ManifestPath string
}

// members returns the workspace members in WorkspaceMembers order, joined to
// their Packages entries for the version and manifest path. Packages not in
// WorkspaceMembers (e.g. path-deps referenced by a member) are filtered out.
//
// Cargo guarantees member names are unique within a workspace, so the (name,
// version) pair safely round-trips through the dep-graph node IDs used by
// the stop-at-other-members logic.
func (m *cargoMetadata) members() []workspaceMember {
	memberIDs := make(map[string]struct{}, len(m.WorkspaceMembers))
	for _, id := range m.WorkspaceMembers {
		memberIDs[id] = struct{}{}
	}

	byID := make(map[string]cargoMetadataPackage, len(m.Packages))
	for _, p := range m.Packages {
		byID[p.ID] = p
	}

	members := make([]workspaceMember, 0, len(m.WorkspaceMembers))
	for _, id := range m.WorkspaceMembers {
		p, ok := byID[id]
		if !ok {
			// Member declared in workspace_members but absent from packages —
			// indicates a metadata-format change worth knowing about. Skip the
			// entry rather than failing the whole scan.
			continue
		}

		members = append(members, workspaceMember{
			Name:         p.Name,
			Version:      p.Version,
			ManifestPath: p.ManifestPath,
		})
	}

	return members
}

// parseMetadata decodes `cargo metadata --no-deps` JSON output.
func parseMetadata(r io.Reader) (*cargoMetadata, error) {
	var m cargoMetadata

	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, fmt.Errorf("decoding cargo metadata JSON: %w", err)
	}

	return &m, nil
}
