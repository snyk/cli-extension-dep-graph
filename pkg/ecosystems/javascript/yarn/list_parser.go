package yarn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// classicListOutput mirrors the single-line JSON object emitted by
// `yarn list --depth=Infinity --json`:
//
//	{"type":"tree","data":{"type":"list","trees":[
//	  {"name":"accepts@1.3.7","children":[{"name":"mime-types@~2.1.24"}, ...]},
//	  ...
//	]}}
//
// Each tree.name is a resolved "name@version". Each child.name is the declared
// specifier as it appears in the parent's package.json — e.g. "mime-types@~2.1.24"
// — which may not exactly match any resolved version. We disambiguate via semver.
type classicListOutput struct {
	Data struct {
		Trees []classicTree `json:"trees"`
	} `json:"data"`
}

type classicTree struct {
	Name     string `json:"name"`
	Children []struct {
		Name string `json:"name"`
	} `json:"children"`
}

// parseYarnListOutput parses Classic `yarn list --depth=Infinity --json` output
// into the unified intermediate.
//
// Algorithm:
//  1. Decode the single JSON line; collect all resolved "name@version" IDs from
//     tree.name as the universe of candidate matches.
//  2. For each tree, resolve each child specifier against that universe via
//     semver — picking the highest version satisfying the declared range.
//  3. Read the root package.json (and any declared workspaces) to derive
//     root-level direct dependencies, which `yarn list` does NOT emit.
//
// Workspaces: if root package.json declares a `workspaces` array, each
// workspace's package.json is read to populate the parsedOutput.Workspaces
// map. Workspace IDs are synthesized in Berry's "name@workspace:dir" form so
// depgraph.go's stop-set logic works uniformly across families.
func parseYarnListOutput(
	ctx context.Context,
	log logger.Logger,
	r io.Reader,
	pkgJSON *packageJSON,
	lockFileDir string,
) (*parsedOutput, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading yarn list output: %w", err)
	}

	var list classicListOutput
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decoding yarn list JSON: %w", err)
	}

	// Universe of resolved IDs available for specifier matching.
	resolved := make([]string, 0, len(list.Data.Trees))
	for _, t := range list.Data.Trees {
		resolved = append(resolved, t.Name)
	}

	out := &parsedOutput{
		Graph:      make(forwardGraph, len(list.Data.Trees)),
		Workspaces: make(map[string]workspaceInfo),
	}

	// Build forward edges from each tree → resolved children.
	for _, t := range list.Data.Trees {
		deps := make(map[string]struct{}, len(t.Children))
		for _, c := range t.Children {
			id := resolveSpecifier(c.Name, resolved)
			if id == "" {
				log.Debug(ctx, "no resolved match for yarn list specifier",
					logger.Attr("parent", t.Name), logger.Attr("specifier", c.Name))
				continue
			}
			deps[id] = struct{}{}
		}
		out.Graph[t.Name] = deps
	}

	// Workspace members come from root package.json's `workspaces` field.
	// Their dependencies aren't emitted by `yarn list` (only the deduped tree
	// at the root is), so we read each workspace's own package.json and
	// semver-match those declared specifiers against the resolved universe too.
	workspaceIDs, err := loadWorkspaces(ctx, log, lockFileDir, pkgJSON, resolved, out)
	if err != nil {
		return nil, err
	}

	// Augment resolved universe with workspace IDs so the root's deps can match
	// against workspace members (e.g. root depends on "@my/logger": "^0.1.0").
	universe := append(append([]string{}, resolved...), workspaceIDs...)

	// Root-direct dependencies come from the root package.json — yarn list does
	// not emit a root-tree entry. Dev deps go in DevDeps; everything else in ProdDeps.
	rootDeps, err := readRootDeps(lockFileDir)
	if err != nil {
		return nil, err
	}
	for spec, isDev := range rootDeps {
		id := resolveSpecifier(spec, universe)
		if id == "" {
			log.Debug(ctx, "no resolved match for root dependency",
				logger.Attr("specifier", spec))
			continue
		}
		if isDev {
			out.DevDeps = append(out.DevDeps, id)
		} else {
			out.ProdDeps = append(out.ProdDeps, id)
		}
	}

	return out, nil
}

// resolveSpecifier matches a declared "name@spec" against a slice of resolved
// "name@version" candidates and returns the best match (highest version that
// satisfies the spec). Returns "" if nothing matches.
//
// For non-semver specifiers (tags, URLs, file:, git:, "*") the function
// degrades gracefully:
//   - exact resolved match in `resolved` → that ID is returned;
//   - otherwise the original specifier is returned verbatim, so the caller can
//     still represent it as a graph node even though it lives outside the
//     resolved set.
func resolveSpecifier(spec string, resolved []string) string {
	name, identifier := splitNameAndIdentifier(spec)
	if name == "" {
		return ""
	}

	// Fast path: exact resolved match (handles non-semver specifiers like tags,
	// URLs, file:, git:, and exact pinned versions in one shot).
	for _, r := range resolved {
		if r == spec {
			return r
		}
	}

	constraint, err := semver.NewConstraint(identifier)
	if err != nil {
		// Not a parseable semver range — surface the raw specifier so the
		// caller still has a graph node to attach.
		return spec
	}

	var (
		bestID  string
		bestVer *semver.Version
	)
	prefix := name + "@"
	for _, r := range resolved {
		if !strings.HasPrefix(r, prefix) {
			continue
		}
		ver := strings.TrimPrefix(r, prefix)
		v, err := semver.NewVersion(ver)
		if err != nil {
			continue
		}
		if !constraint.Check(v) {
			continue
		}
		if bestVer == nil || v.GreaterThan(bestVer) {
			bestID = r
			bestVer = v
		}
	}
	return bestID
}

// splitNameAndIdentifier splits "name@spec" at the last '@' that is not at
// position 0, so scoped packages ("@scope/name@1.0.0") are handled correctly.
// For inputs with no version component, returns ("", "").
func splitNameAndIdentifier(s string) (name, identifier string) {
	i := strings.LastIndex(s, "@")
	if i <= 0 {
		return "", ""
	}
	return s[:i], s[i+1:]
}

// loadWorkspaces reads each workspace's package.json (per the root's
// `workspaces` field), synthesizes a "name@workspace:dir" ID for each, and
// populates Graph + Workspaces. Returns the list of synthesized IDs so the
// caller can extend its resolved universe.
//
// Workspace globs (e.g. "packages/*") are expanded via filepath.Glob — yarn
// itself uses minimatch which has richer semantics, but * suffices for the
// overwhelmingly common case. Workspaces declared with deeper patterns
// (**/foo) won't be picked up; the consumer's `yarn list` output still
// describes the deduped tree correctly, only the per-workspace dep graph
// emission is skipped for those.
func loadWorkspaces(
	ctx context.Context,
	log logger.Logger,
	lockFileDir string,
	pkgJSON *packageJSON,
	resolved []string,
	out *parsedOutput,
) ([]string, error) {
	if pkgJSON == nil || len(pkgJSON.Workspaces.Packages) == 0 {
		return nil, nil
	}

	var ids []string
	for _, glob := range pkgJSON.Workspaces.Packages {
		matches, err := filepath.Glob(filepath.Join(lockFileDir, glob))
		if err != nil {
			log.Debug(ctx, "skipping invalid workspaces glob",
				logger.Attr("glob", glob), logger.Attr("err", err.Error()))
			continue
		}
		for _, m := range matches {
			info, statErr := os.Stat(m)
			if statErr != nil || !info.IsDir() {
				continue
			}
			wsRel, err := filepath.Rel(lockFileDir, m)
			if err != nil {
				continue
			}

			wsPJ, err := readPackageJSON(m)
			if err != nil {
				log.Debug(ctx, "skipping workspace with unreadable package.json",
					logger.Attr("dir", wsRel), logger.Attr("err", err.Error()))
				continue
			}
			if wsPJ.Name == "" {
				log.Debug(ctx, "skipping unnamed workspace package.json",
					logger.Attr("dir", wsRel))
				continue
			}

			wsID := wsPJ.Name + "@workspace:" + wsRel

			// Workspace's direct deps come from its own package.json. We match
			// declared specifiers against the resolved universe so transitive
			// edges from the workspace land in the unified Graph.
			wsDeps := make(map[string]struct{})
			for spec := range workspaceDirectSpecs(m) {
				id := resolveSpecifier(spec, resolved)
				if id == "" {
					log.Debug(ctx, "no resolved match for workspace dependency",
						logger.Attr("workspace", wsRel), logger.Attr("specifier", spec))
					continue
				}
				wsDeps[id] = struct{}{}
			}

			out.Graph[wsID] = wsDeps
			out.Workspaces[wsID] = workspaceInfo{
				Dir:     wsRel,
				Name:    wsPJ.Name,
				Version: wsPJ.Version,
			}
			ids = append(ids, wsID)
		}
	}
	return ids, nil
}

// workspaceDirectSpecs reads a workspace's package.json and returns the set
// of declared dep specifiers (across dependencies + devDependencies +
// optionalDependencies + peerDependencies). The set form lets the caller
// resolve each specifier independently without caring about its kind.
func workspaceDirectSpecs(dir string) map[string]struct{} {
	specs := make(map[string]struct{})
	collect := func(deps map[string]string) {
		for name, version := range deps {
			specs[name+"@"+version] = struct{}{}
		}
	}

	type fullPkgJSON struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}

	data, err := os.ReadFile(filepath.Join(dir, packageJSONFile))
	if err != nil {
		return specs
	}
	var p fullPkgJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return specs
	}
	collect(p.Dependencies)
	collect(p.DevDependencies)
	collect(p.OptionalDependencies)
	collect(p.PeerDependencies)
	return specs
}

// readRootDeps returns the root project's direct deps as a map from declared
// specifier (e.g. "accepts@1.3.7") to isDev flag. Optional/peer deps are
// treated as production by convention.
func readRootDeps(dir string) (map[string]bool, error) {
	type fullPkgJSON struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}

	data, err := os.ReadFile(filepath.Join(dir, packageJSONFile))
	if err != nil {
		return nil, fmt.Errorf("reading root package.json: %w", err)
	}
	var p fullPkgJSON
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing root package.json: %w", err)
	}

	out := make(map[string]bool, len(p.Dependencies)+len(p.DevDependencies))
	add := func(deps map[string]string, isDev bool) {
		for name, version := range deps {
			out[name+"@"+version] = isDev
		}
	}
	add(p.Dependencies, false)
	add(p.OptionalDependencies, false)
	add(p.PeerDependencies, false)
	add(p.DevDependencies, true)
	return out, nil
}
