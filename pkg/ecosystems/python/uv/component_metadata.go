package uv

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/componentmetadata"
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// minComponentMetadataVersion is the first uv whose CycloneDX export gives
// each distribution reference a hash (astral-sh/uv#21131). Older versions
// list no distributions at all.
var minComponentMetadataVersion = Version{0, 12, 5}

// prunedLabel marks a stub standing in for a node expanded elsewhere.
// sbom-export folds the stub into its full node, so the stub carries only
// this label, as for the other ecosystems.
const prunedLabel = "pruned"

// supportsComponentMetadata reports whether a uv of this version exports
// hashed distribution references. An unknown version does not.
func supportsComponentMetadata(uvVersion string) bool {
	m := versionPattern.FindStringSubmatch(uvVersion)
	if m == nil {
		return false
	}
	v := Version{mustAtoi(m[1]), mustAtoi(m[2]), mustAtoi(m[3])}
	return compareVersions(v, minComponentMetadataVersion) >= 0
}

// exportReferences is the part of a uv CycloneDX export that lists each
// component's published files. Components are decoded one at a time, so a
// component that cannot be read loses only its own labels.
type exportReferences struct {
	Metadata struct {
		Component json.RawMessage `json:"component"`
	} `json:"metadata"`
	Components []json.RawMessage `json:"components"`
}

// componentIdentity is decoded on its own, so that a component whose
// references cannot be read still takes part in duplicate detection.
type componentIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type componentReferences struct {
	ExternalReferences []struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Hashes []struct {
			Alg     string `json:"alg"`
			Content string `json:"content"`
		} `json:"hashes"`
	} `json:"externalReferences"`
}

// labelComponents labels the converter's graphs with the artifact metadata in
// the export they were converted from. It never fails the scan: an export it
// cannot read leaves the graphs as the converter returned them.
func labelComponents(ctx context.Context, log logger.Logger, sbom Sbom, graphs []*depgraph.DepGraph, lockFilePath string) {
	index, err := componentLabelIndex(sbom)
	if err != nil {
		log.Info(ctx, "Leaving uv packages without component metadata",
			logger.Attr("lockFile", lockFilePath), logger.Err(err)) //nolint:goconst // logger key, not worth a constant
		return
	}
	for _, dg := range graphs {
		applyComponentLabels(dg, index)
	}
}

// componentLabelIndex maps each package, by normalised name and exact
// version, to the labels of the artifact chosen from its distributions. Only
// an export that is not a JSON document with a components array fails it.
//
// The converter's nodes carry only a name and version, so two components that
// share them cannot be told apart on the graph. When their labels differ,
// neither is labeled: naming one artifact for both would put the wrong hash
// on one of them. The root component takes part too, since a project can
// share a name@version with a registry package.
func componentLabelIndex(sbom Sbom) (map[string]componentmetadata.Labels, error) {
	var doc exportReferences
	if err := json.Unmarshal(sbom, &doc); err != nil {
		return nil, fmt.Errorf("reading distribution references: %w", err)
	}
	components := doc.Components
	if len(doc.Metadata.Component) > 0 && string(doc.Metadata.Component) != "null" {
		components = append([]json.RawMessage{doc.Metadata.Component}, components...)
	}

	index := map[string]componentmetadata.Labels{}
	conflicting := map[string]bool{}
	for _, raw := range components {
		var id componentIdentity
		if err := json.Unmarshal(raw, &id); err != nil {
			// Without a name and version there is no node to label.
			continue
		}
		key := packageKey(id.Name, id.Version)
		if conflicting[key] {
			continue
		}
		labels := componentmetadata.Labels{}
		var refs componentReferences
		if err := json.Unmarshal(raw, &refs); err == nil {
			labels = artifactLabelsFor(&refs)
		}
		if seen, ok := index[key]; ok {
			if !maps.Equal(seen, labels) {
				delete(index, key)
				conflicting[key] = true
			}
			continue
		}
		index[key] = labels
	}
	return index, nil
}

// artifactLabelsFor labels a component with the hashes and URL of the file
// selectPythonArtifact picks from its distributions. Workspace members and
// path, git, directory and editable sources list none and get no labels.
//
// When the chosen file's URL is rejected (an auth segment, or a file:// URL)
// its hash is still labeled: it describes the selected file all the same, as
// in the other producers.
func artifactLabelsFor(c *componentReferences) componentmetadata.Labels {
	labels := componentmetadata.Labels{}
	var files []pythonArtifact
	for _, ref := range c.ExternalReferences {
		if ref.Type != "distribution" || ref.URL == "" {
			continue
		}
		hashes := make(map[string]string, len(ref.Hashes))
		for _, h := range ref.Hashes {
			hashes[h.Alg] = h.Content
		}
		files = append(files, pythonArtifact{Filename: artifactFilename(ref.URL), URL: ref.URL, Hashes: hashes})
	}
	chosen, ok := selectPythonArtifact(files)
	if !ok {
		return labels
	}
	for _, alg := range slices.Sorted(maps.Keys(chosen.Hashes)) {
		labels.AddHash(alg, chosen.Hashes[alg])
	}
	labels.AddDistributionURL(chosen.URL)
	return labels
}

// artifactFilename is the URL-decoded last path segment, which names the
// sdist or wheel. It is split before decoding so that an encoded slash stays
// inside the name.
func artifactFilename(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	escaped := u.EscapedPath()
	last := escaped[strings.LastIndex(escaped, "/")+1:]
	name, err := url.PathUnescape(last)
	if err != nil {
		return last
	}
	return name
}

// applyComponentLabels joins the index onto every node by its package's name
// and version, not its node ID: the converter suffixes IDs ("pkg@1.0|2") when
// a package occurs under several bom-refs.
func applyComponentLabels(dg *depgraph.DepGraph, index map[string]componentmetadata.Labels) {
	pkgs := make(map[string]depgraph.PkgInfo, len(dg.Pkgs))
	for _, p := range dg.Pkgs {
		pkgs[p.ID] = p.Info
	}
	for i := range dg.Graph.Nodes {
		node := &dg.Graph.Nodes[i]
		if node.Info != nil && node.Info.Labels[prunedLabel] == "true" {
			continue
		}
		info, ok := pkgs[node.PkgID]
		if !ok {
			continue
		}
		index[packageKey(info.Name, info.Version)].ApplyTo(node)
	}
}

var nameSeparators = regexp.MustCompile(`[-_.]+`)

// packageKey identifies a package by its PEP 503 normalised name and its exact
// version string.
func packageKey(name, version string) string {
	return nameSeparators.ReplaceAllString(strings.ToLower(name), "-") + "@" + version
}
