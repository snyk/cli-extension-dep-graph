package yarn

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

const logFieldDir = "dir"

// `yarn list --depth=Infinity --json` emits NDJSON, one envelope per line:
//
//	{"type":"warning","data":"package.json: No license field"}
//	{"type":"warning","data":"<pkg>: No license field"}
//	{"type":"tree","data":{"type":"list","trees":[
//	  {"name":"accepts@1.3.7","children":[{"name":"mime-types@~2.1.24"}, ...]},
//	  ...
//	]}}
//
// Real customer projects routinely have warnings before the tree (missing
// license, missing description, peer-dep mismatches). We must scan line by
// line and pick the envelope with type:"tree" — naive whole-buffer JSON
// decoding fails the moment a single warning shows up.
//
// Each tree.name is a resolved "name@version". Each child.name is the declared
// specifier as it appears in the parent's package.json — e.g.
// "mime-types@~2.1.24" — which may not exactly match any resolved version.
// We disambiguate via semver.
type classicListEnvelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type classicListTreeData struct {
	Trees []classicTree `json:"trees"`
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
	trees, err := readClassicTrees(ctx, log, r)
	if err != nil {
		return nil, err
	}

	// Lockfile pre-pass: builds a map from each declared specifier ever
	// written into package.json (URLs, git URLs, tarballs, npm: aliases,
	// exact pins, semver ranges) to its resolved "name@version" form. This
	// is what lets non-semver specifiers like
	//   "body-parser": "https://example.com/body-parser-1.9.0.tar.gz"
	// or
	//   "lodash": "npm:lodash@^4.17.15"
	// resolve to the right resolved package without us having to re-implement
	// yarn's specifier resolution. Missing lockfile is non-fatal — the
	// semver and raw-spec fallbacks in resolveSpecifier still work.
	lockResolutions, err := readYarnLockResolutions(lockFileDir)
	if err != nil {
		log.Debug(ctx, "yarn.lock pre-pass failed; proceeding without",
			logger.Err(err))
		lockResolutions = nil
	}

	// Universe of resolved IDs available for specifier matching.
	resolved := make([]string, 0, len(trees))
	for _, t := range trees {
		resolved = append(resolved, t.Name)
	}

	out := &parsedOutput{
		Graph:      make(forwardGraph, len(trees)),
		Workspaces: make(map[string]workspaceInfo),
	}

	// Build forward edges from each tree → resolved children.
	for _, t := range trees {
		deps := make(map[string]struct{}, len(t.Children))
		for _, c := range t.Children {
			id := resolveSpecifier(c.Name, resolved, lockResolutions)
			if id == "" {
				log.Debug(ctx, "no resolved match for yarn list specifier",
					logger.Attr("parent", t.Name), logger.Attr("specifier", c.Name))
				continue
			}
			deps[id] = struct{}{}
		}
		out.Graph[t.Name] = deps
	}

	// Workspace members are identified from the root package.json's `workspaces`
	// field. Yarn list ALREADY emits workspace packages as regular "name@version"
	// trees (and cross-workspace edges as regular children) — see
	// pkg-a@1.0.0 -> pkg-b@1.0.0 in the workspace-with-cross-ref fixture. We
	// just need to flag which of those tree entries are workspaces so depgraph.go
	// emits a separate dep graph per workspace and treats sibling workspaces as
	// leaves in non-owner graphs.
	markWorkspaces(ctx, log, lockFileDir, pkgJSON, out)

	// Root-direct dependencies come from the root package.json — yarn list does
	// not emit a root-tree entry. Dev deps go in DevDeps; everything else in ProdDeps.
	rootDeps, err := readRootDeps(lockFileDir)
	if err != nil {
		return nil, err
	}
	for spec, isDev := range rootDeps {
		id := resolveSpecifier(spec, resolved, lockResolutions)
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

// readClassicTrees scans the NDJSON stream from `yarn list --json` line by
// line and returns the trees from the (single) envelope whose type is "tree".
// Warning / error / info envelopes are logged and skipped; non-JSON lines are
// tolerated for robustness against future yarn changes.
//
// Real-world `yarn list` output for a project that lacks a license field or
// has any other manifest validation finding has one or more warning lines
// BEFORE the tree, so a naive whole-buffer json.Unmarshal would fail. Scanning
// line by line is required for parity with what customers actually run.
func readClassicTrees(ctx context.Context, log logger.Logger, r io.Reader) ([]classicTree, error) {
	scanner := bufio.NewScanner(r)
	// yarn list can emit very large tree envelopes for monorepos (5k+ packages).
	// Default 64KB is too small; allow up to 16MB per line.
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 16*1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		var env classicListEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			log.Debug(ctx, "Skipping unparseable yarn list line",
				logger.Attr("line", lineNum), logger.Err(err))
			continue
		}

		switch env.Type {
		case "tree":
			var data classicListTreeData
			if err := json.Unmarshal(env.Data, &data); err != nil {
				return nil, fmt.Errorf("decoding yarn list tree payload: %w", err)
			}
			return data.Trees, nil

		case "warning", "info", "step", "success":
			// Non-fatal envelopes — log at debug. yarn emits warning for
			// missing-license, missing-description, peer-dep mismatches, etc.;
			// none of those affect the resolved graph.
			log.Debug(ctx, "yarn list envelope",
				logger.Attr("type", env.Type), logger.Attr("data", string(env.Data)))

		case "error":
			// yarn list does emit error envelopes for situations like a
			// "file:" dep pointing at a missing path. We surface those so the
			// plugin's per-file result carries the explanation instead of
			// silently producing an empty graph.
			return nil, fmt.Errorf("yarn list reported error: %s", string(env.Data))

		default:
			log.Debug(ctx, "unrecognized yarn list envelope type",
				logger.Attr("type", env.Type))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning yarn list output: %w", err)
	}
	return nil, fmt.Errorf("yarn list output contained no tree envelope")
}

// resolveSpecifier maps a declared "name@spec" to a resolved "name@version"
// ID. Lookup order:
//
//  1. Exact match in `resolved` — covers already-resolved specs and exact
//     pins that match a tree entry verbatim (e.g. cross-workspace refs).
//  2. Lockfile spec table — covers anything yarn captured in yarn.lock,
//     including URLs, git URLs, tarballs, and npm: aliases. yarn.lock keys
//     are the verbatim specifiers from package.json, so the lookup is exact
//     and unambiguous.
//  3. Semver constraint matching against `resolved` — covers ^, ~, >=, ranges.
//     Picks the highest version satisfying the constraint.
//  4. Raw spec fallback — non-semver specs that aren't in the lockfile (rare:
//     tag-only specs like "latest" with no resolved counterpart in trees).
//     Surfaced verbatim so the caller still has a graph node to attach.
//
// `lockResolutions` may be nil; in that case step 2 is skipped.
func resolveSpecifier(spec string, resolved []string, lockResolutions map[string]string) string {
	name, identifier := splitNameAndIdentifier(spec)
	if name == "" {
		return ""
	}

	// 1. Fast path: exact resolved match.
	for _, r := range resolved {
		if r == spec {
			return r
		}
	}

	// 2. Lockfile spec → resolved version lookup. yarn.lock keys are exact
	//    package.json specifiers, so URL / git / alias deps resolve here.
	if lockResolutions != nil {
		if id, ok := lockResolutions[spec]; ok {
			return id
		}
	}

	constraint, err := semver.NewConstraint(identifier)
	if err != nil {
		// Not a parseable semver range and not in the lockfile — surface the
		// raw specifier so the caller still has a graph node to attach.
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

// yarn.lock v1 format used by readYarnLockResolutions:
//
//	# header — one or more comma-separated specifiers, then ":"
//	"body-parser@https://example.com/body-parser-1.9.0.tar.gz":
//	bytes@1, bytes@1.0.0:
//	  version "1.0.0"
//	  resolved "..."
//
// We capture every header's specifier list, then assign each to the version
// from the following `  version "X"` line. Comments and blanks are ignored.
var lockVersionLine = regexp.MustCompile(`^\s+version\s+"([^"]+)"\s*$`)

// readYarnLockResolutions reads <dir>/yarn.lock and returns a map from each
// declared specifier ever written into package.json (the verbatim header)
// to its resolved "name@version" form. Lets non-semver specs (URLs, git,
// tarballs, npm: aliases) resolve without us re-implementing yarn's logic.
//
// Missing or unreadable yarn.lock returns (nil, err); callers should log the
// error and proceed with a nil map — resolveSpecifier degrades to semver and
// raw-spec fallbacks. Comma-separated specs in a single header all share
// the resolved version (yarn dedupes equivalent specs into one entry).
func readYarnLockResolutions(lockFileDir string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(lockFileDir, yarnLockFile))
	if err != nil {
		return nil, fmt.Errorf("reading yarn.lock: %w", err)
	}
	return parseYarnLockResolutions(data), nil
}

func parseYarnLockResolutions(data []byte) map[string]string {
	out := make(map[string]string)
	var pending []string // specs awaiting a version line

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Header: starts in column 0, ends with ":".
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			pending = pending[:0]
			header := strings.TrimSuffix(line, ":")
			for _, raw := range strings.Split(header, ",") {
				spec := strings.TrimSpace(raw)
				spec = strings.Trim(spec, `"`)
				if spec != "" {
					pending = append(pending, spec)
				}
			}
			continue
		}

		if m := lockVersionLine.FindStringSubmatch(line); m != nil && len(pending) > 0 {
			version := m[1]
			for _, spec := range pending {
				if name := nameFromSpec(spec); name != "" {
					out[spec] = name + "@" + version
				}
			}
			pending = pending[:0]
		}
	}
	return out
}

// nameFromSpec extracts the package name from a "name@spec" string. Splits
// at the FIRST '@' after the optional scope prefix, so identifier payloads
// that themselves contain '@' (npm: aliases like "lodash@npm:lodash@^4.17",
// URL specs that may carry userinfo like "pkg@https://user:tok@host/...") are
// kept intact as the identifier.
//
//	"accepts@1.3.7"                                          → "accepts"
//	"@types/node@25.5.2"                                     → "@types/node"
//	"lodash@npm:lodash@^4.17.15"                             → "lodash"
//	"body-parser@https://user:tok@host.example/x.tar.gz"     → "body-parser"
//	"@scope/pkg@npm:@scope/other@^1"                         → "@scope/pkg"
func nameFromSpec(spec string) string {
	if spec == "" {
		return ""
	}
	offset := 0
	if strings.HasPrefix(spec, "@") {
		slash := strings.Index(spec, "/")
		if slash < 0 {
			return ""
		}
		offset = slash + 1
	}
	idx := strings.Index(spec[offset:], "@")
	if idx <= 0 {
		return ""
	}
	return spec[:offset+idx]
}

// splitNameAndIdentifier splits "name@spec" into the package name and the
// declared identifier (semver range, URL, git URL, npm: alias). Uses the
// same first-non-scope-'@' rule as nameFromSpec, so identifiers that embed
// '@' (npm: aliases, URLs carrying userinfo) survive intact.
//
// For inputs with no version component, returns ("", "").
func splitNameAndIdentifier(s string) (name, identifier string) {
	name = nameFromSpec(s)
	if name == "" {
		return "", ""
	}
	return name, s[len(name)+1:]
}

// markWorkspaces reads each workspace's package.json (per the root's
// `workspaces` field) and flags the matching tree entry in parsedOutput as a
// workspace member. We do NOT synthesize new IDs: yarn list emits workspace
// packages as regular "name@version" trees (and cross-workspace edges as
// regular children — see workspace-with-cross-ref fixture), so the existing
// Graph entry already has the right deps. depgraph.go uses Workspaces solely
// to know which Graph nodes need their own dep-graph result and which to
// treat as leaves in non-owner graphs.
//
// Workspace globs (e.g. "packages/*") are expanded via filepath.Glob — yarn
// itself uses minimatch which has richer semantics, but * suffices for the
// overwhelmingly common case. Workspaces declared with deeper patterns
// (**/foo) won't be picked up; the consumer's `yarn list` output still
// describes the deduped tree correctly, only the per-workspace dep graph
// emission is skipped for those.
func markWorkspaces(
	ctx context.Context,
	log logger.Logger,
	lockFileDir string,
	pkgJSON *packageJSON,
	out *parsedOutput,
) {
	if pkgJSON == nil || len(pkgJSON.Workspaces.Packages) == 0 {
		return
	}

	for _, glob := range pkgJSON.Workspaces.Packages {
		matches, globErr := filepath.Glob(filepath.Join(lockFileDir, glob))
		if globErr != nil {
			log.Debug(ctx, "skipping invalid workspaces glob",
				logger.Attr("glob", glob), logger.Err(globErr))
			continue
		}
		for _, m := range matches {
			info, statErr := os.Stat(m)
			if statErr != nil || !info.IsDir() {
				continue
			}
			wsRel, relErr := filepath.Rel(lockFileDir, m)
			if relErr != nil {
				continue
			}

			wsPJ, readErr := readPackageJSON(m)
			if readErr != nil {
				log.Debug(ctx, "skipping workspace with unreadable package.json",
					logger.Attr(logFieldDir, wsRel), logger.Err(readErr))
				continue
			}
			if wsPJ.Name == "" {
				log.Debug(ctx, "skipping unnamed workspace package.json",
					logger.Attr(logFieldDir, wsRel))
				continue
			}

			version := wsPJ.Version
			if version == "" {
				version = defaultVersion
			}
			wsID := wsPJ.Name + "@" + version

			// Only register if yarn list emitted a tree entry for this
			// workspace at this version. If not (e.g. workspace's
			// package.json version diverged from what yarn used), log and
			// skip — registering would yield a workspace dep graph with
			// no transitive deps.
			if _, ok := out.Graph[wsID]; !ok {
				log.Debug(ctx, "workspace package.json version not in yarn list trees; skipping",
					logger.Attr("workspace", wsRel), logger.Attr("id", wsID))
				continue
			}
			out.Workspaces[wsID] = workspaceInfo{
				Dir:     wsRel,
				Name:    wsPJ.Name,
				Version: version,
			}
		}
	}
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
