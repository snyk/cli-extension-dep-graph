package pnpm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// Rush keeps its shared pnpm lockfile at common/config/rush/pnpm-lock.yaml and
// does NOT commit a pnpm-workspace.yaml (it generates one under common/temp at
// `rush install`). To resolve the lockfile on a clean checkout without
// installing, we recreate that generated layout in a throwaway tmp tree (so the
// scanned repo is never mutated): a common/temp/ holding the lockfile copy + a
// synthesized pnpm-workspace.yaml whose `packages:` are ../../<projectFolder>,
// plus each project's package.json copied to ../../<projectFolder>/package.json
// so those relative paths resolve within the tmp tree.

const (
	rushSubspacesConfig = "common/config/rush/subspaces.json"
	rushLockfilePath    = "common/config/rush/pnpm-lock.yaml"
	rushImporterBase    = "common/temp"
)

// errRushNotPnpm is returned for an npm/yarn-backed Rush repo (pnpm-only scope).
var errRushNotPnpm = errors.New("not a pnpm-backed Rush monorepo; only Rush + pnpm is supported")

// errRushSubspaces is returned when subspaces are enabled (out of scope): the
// monorepo-level lockfile is forbidden, so scanning it would yield wrong
// results. Skip rather than scan an incomplete lockfile.
var errRushSubspaces = errors.New("rush subspaces are not yet supported (common/config/rush/subspaces.json present)")

// rush.json is JSONC (comments + trailing commas); test for fields rather than
// JSON-parsing.
var (
	rushPnpmVersionRe   = regexp.MustCompile(`"pnpmVersion"\s*:`)
	rushProjectFolderRe = regexp.MustCompile(`"projectFolder"\s*:\s*"([^"]+)"`)

	// JSONC comment strippers so a commented-out block (e.g. an old
	// `/* "pnpmVersion": "7" */`) can't false-trigger the pnpm gate or inject a
	// phantom project folder. Line stripping only removes whole-line `//`
	// comments to avoid clobbering `//` inside string values (e.g. the $schema URL).
	rushBlockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	rushLineCommentRe  = regexp.MustCompile(`(?m)^\s*//.*$`)
)

// rushTargets is the Rush adapter: detects a pnpm-backed Rush monorepo, stages
// the common/temp workspace context Rush generates at install time, and returns
// a single scan target whose cleanup tears the tmp tree down.
//
// Out-of-scope Rush repos (npm/yarn-backed, subspaces) return (nil, nil) so the
// scan ends quietly with a skip log. Unexpected setup failures return one
// errTarget so they surface as an SCAResult rather than aborting the scan.
func rushTargets(ctx context.Context, log logger.Logger, rushDir string) ([]scanTarget, error) {
	log.Info(ctx, "Building Rush + pnpm dependency graphs", logger.Attr(logFieldDir, rushDir))

	folders, err := rushProjectFolders(rushDir)
	if err != nil {
		if errors.Is(err, errRushNotPnpm) || errors.Is(err, errRushSubspaces) {
			log.Info(ctx, "Skipping Rush workspace", logger.Attr("reason", err.Error()))
			return nil, nil
		}
		return []scanTarget{errTarget(rushJSONFile, fmt.Errorf("reading rush.json: %w", err))}, nil
	}

	runDir, scanRoot, skipped, cleanup, err := stageRushWorkspace(rushDir, folders)
	if err != nil {
		return []scanTarget{errTarget(rushJSONFile, err)}, nil
	}

	if len(skipped) > 0 {
		// User-visible surfacing of skips is part of the deferred FF+wiring
		// work; for now log so a stale/renamed project folder doesn't silently
		// vanish from a scan that otherwise succeeds.
		log.Info(ctx, "Skipping Rush projects with no readable package.json",
			logger.Attr("projects", strings.Join(skipped, ", ")))
	}

	return []scanTarget{{
		cmdDir:          runDir,
		manifestBaseDir: scanRoot,
		excludeDir:      runDir, // the synthetic "rush-common" aggregate lives here
		processedFiles:  []string{rushJSONFile, filepath.FromSlash(rushLockfilePath)},
		errTargetFile:   rushJSONFile,
		cleanup:         cleanup,
	}}, nil
}

// stripJSONComments removes JSONC block and full-line comments from rush.json.
func stripJSONComments(data []byte) []byte {
	data = rushBlockCommentRe.ReplaceAll(data, nil)
	return rushLineCommentRe.ReplaceAll(data, nil)
}

// isRushRoot reports whether dir contains a rush.json.
func isRushRoot(dir string) bool {
	return fileExists(filepath.Join(dir, rushJSONFile))
}

// rushProjectFolders parses the project folders out of rush.json, and validates
// the repo is pnpm-backed and not using subspaces.
func rushProjectFolders(rushDir string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(rushDir, rushJSONFile))
	if err != nil {
		return nil, fmt.Errorf("reading rush.json: %w", err)
	}
	data = stripJSONComments(data)
	if !rushPnpmVersionRe.Match(data) {
		return nil, errRushNotPnpm //nolint:wrapcheck // sentinel matched with errors.Is by the caller
	}
	if fileExists(filepath.Join(rushDir, filepath.FromSlash(rushSubspacesConfig))) {
		return nil, errRushSubspaces //nolint:wrapcheck // sentinel matched with errors.Is by the caller
	}

	var folders []string
	for _, m := range rushProjectFolderRe.FindAllSubmatch(data, -1) {
		folders = append(folders, string(m[1]))
	}
	return folders, nil
}

// stageRushWorkspace recreates, in a throwaway tmp tree, the common/temp/
// workspace context Rush generates at install time, so `pnpm list
// --lockfile-only` can resolve the shared lockfile without mutating the scanned
// repo. Returns runDir (where pnpm runs, = <tmp>/common/temp), scanRoot (the
// tmp root, used as the base for package.json relative paths — structurally
// identical to the real repo root), the project folders that were skipped
// because they had no readable package.json, and a cleanup func.
//
// A project folder listed in rush.json but missing its package.json on disk
// (stale/renamed/decoupled) is skipped, not fatal — pnpm tolerates a member
// present in the lockfile but absent from pnpm-workspace.yaml. Only a workspace
// with zero readable projects is an error.
func stageRushWorkspace(rushDir string, projectFolders []string) (runDir, scanRoot string, skipped []string, cleanup func(), err error) {
	lockBytes, err := os.ReadFile(filepath.Join(rushDir, filepath.FromSlash(rushLockfilePath)))
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("reading Rush lockfile: %w", err)
	}

	tmpRoot, err := os.MkdirTemp("", "snyk-rush-pnpm-*")
	if err != nil {
		return "", "", nil, nil, fmt.Errorf("creating staging dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(tmpRoot) }

	// Copy each project's package.json into the mirrored tree so the ../../
	// importer paths resolve. Only package.json is needed — pnpm list
	// --lockfile-only reads manifests + the lockfile, never node_modules.
	var stagedFolders []string
	for _, pf := range projectFolders {
		src := filepath.Join(rushDir, filepath.FromSlash(pf), packageJSONFile)
		data, readErr := os.ReadFile(src)
		if readErr != nil {
			skipped = append(skipped, pf)
			continue
		}
		dstDir := filepath.Join(tmpRoot, filepath.FromSlash(pf))
		if mkErr := os.MkdirAll(dstDir, 0o750); mkErr != nil {
			cleanup()
			return "", "", nil, nil, fmt.Errorf("staging %s: %w", pf, mkErr)
		}
		if wErr := os.WriteFile(filepath.Join(dstDir, packageJSONFile), data, 0o600); wErr != nil {
			cleanup()
			return "", "", nil, nil, fmt.Errorf("staging %s/package.json: %w", pf, wErr)
		}
		stagedFolders = append(stagedFolders, pf)
	}
	if len(stagedFolders) == 0 {
		cleanup()
		return "", "", nil, nil, fmt.Errorf("no Rush projects with a readable package.json found under %s", rushDir)
	}

	staged := filepath.Join(tmpRoot, filepath.FromSlash(rushImporterBase))
	if mkErr := os.MkdirAll(staged, 0o750); mkErr != nil {
		cleanup()
		return "", "", nil, nil, fmt.Errorf("creating common/temp: %w", mkErr)
	}

	files := map[string][]byte{
		pnpmLockFile:          lockBytes,
		"pnpm-workspace.yaml": workspaceYAML(stagedFolders),
		// The generated "." importer aggregate, filtered from results by path.
		packageJSONFile: []byte(`{"name":"rush-common","version":"0.0.0","private":true,"dependencies":{}}`),
	}
	for name, data := range files {
		if wErr := os.WriteFile(filepath.Join(staged, name), data, 0o600); wErr != nil {
			cleanup()
			return "", "", nil, nil, fmt.Errorf("staging %s: %w", name, wErr)
		}
	}

	return staged, tmpRoot, skipped, cleanup, nil
}

func workspaceYAML(projectFolders []string) []byte {
	ws := "packages:\n"
	for _, pf := range projectFolders {
		ws += "  - ../../" + pf + "\n"
	}
	return []byte(ws)
}
