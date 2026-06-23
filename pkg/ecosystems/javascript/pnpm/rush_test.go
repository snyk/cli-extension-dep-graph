package pnpm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

func TestStripJSONComments(t *testing.T) {
	tests := []struct {
		name           string
		in             string
		mustNotContain []string
		mustContain    []string
	}{
		{
			name:           "block comment removed",
			in:             `{ /* "pnpmVersion": "7.0.0", */ "npmVersion": "9.0.0" }`,
			mustNotContain: []string{"pnpmVersion"},
			mustContain:    []string{"npmVersion"},
		},
		{
			name:           "whole-line comment removed",
			in:             "{\n  // \"pnpmVersion\": \"7.0.0\",\n  \"npmVersion\": \"9.0.0\"\n}",
			mustNotContain: []string{"pnpmVersion"},
			mustContain:    []string{"npmVersion"},
		},
		{
			name:        "inline // inside a string value is preserved",
			in:          "{\n  \"$schema\": \"https://example.com/v5/rush.schema.json\",\n  \"pnpmVersion\": \"8.15.8\"\n}",
			mustContain: []string{"https://example.com", "pnpmVersion"},
		},
		{
			name:        "real config untouched",
			in:          "{\n  \"pnpmVersion\": \"8.15.8\",\n  \"projects\": [{ \"projectFolder\": \"apps/a\" }]\n}",
			mustContain: []string{"pnpmVersion", "apps/a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(stripJSONComments([]byte(tt.in)))
			for _, s := range tt.mustNotContain {
				if strings.Contains(got, s) {
					t.Errorf("stripped output should not contain %q; got:\n%s", s, got)
				}
			}
			for _, s := range tt.mustContain {
				if !strings.Contains(got, s) {
					t.Errorf("stripped output should contain %q; got:\n%s", s, got)
				}
			}
		})
	}
}

// TestRushSubspacesEnabled covers the field-aware subspaces detection that
// replaced the old "file exists" check. Only a literal "subspacesEnabled": true
// should report enabled; everything else (absent file, false, missing field,
// malformed JSON) is the Rush default of disabled.
func TestRushSubspacesEnabled(t *testing.T) {
	tests := []struct {
		name    string
		content string // "" means: do not create the file at all
		write   bool
		want    bool
	}{
		{name: "file absent", write: false, want: false},
		{name: "enabled true", write: true, content: `{"subspacesEnabled": true, "subspaceNames": ["default"]}`, want: true},
		{name: "enabled false", write: true, content: `{"subspacesEnabled": false, "subspaceNames": []}`, want: false},
		{name: "field missing", write: true, content: `{"subspaceNames": ["default"]}`, want: false},
		{name: "empty object", write: true, content: `{}`, want: false},
		{name: "malformed json", write: true, content: `{ this is not json`, want: false},
		{name: "enabled true among other fields", write: true, content: `{"$schema":"x","subspaceNames":[],"subspacesEnabled":true}`, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "subspaces.json")
			if tt.write {
				if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
					t.Fatalf("writing fixture: %v", err)
				}
			}
			if got := rushSubspacesEnabled(path); got != tt.want {
				t.Errorf("rushSubspacesEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// writeRushRepo stages a minimal Rush repo under a fresh temp dir and returns
// its root. files maps repo-relative slash paths to contents; parent dirs are
// created as needed.
func writeRushRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", rel, err)
		}
	}
	return root
}

const rushJSONPnpm = `{
  "pnpmVersion": "8.15.8",
  "projects": [
    { "packageName": "@x/app-a", "projectFolder": "apps/app-a" },
    { "packageName": "@x/lib-b", "projectFolder": "libs/lib-b" }
  ]
}`

func TestRushProjectFolders(t *testing.T) {
	t.Run("pnpm-backed returns project folders", func(t *testing.T) {
		root := writeRushRepo(t, map[string]string{rushJSONFile: rushJSONPnpm})

		folders, err := rushProjectFolders(root)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		sort.Strings(folders)
		want := []string{"apps/app-a", "libs/lib-b"}
		if len(folders) != len(want) || folders[0] != want[0] || folders[1] != want[1] {
			t.Errorf("folders = %v, want %v", folders, want)
		}
	})

	t.Run("npm-backed is errRushNotPnpm", func(t *testing.T) {
		root := writeRushRepo(t, map[string]string{
			rushJSONFile: `{ "npmVersion": "9.0.0", "projects": [{ "projectFolder": "apps/a" }] }`,
		})
		_, err := rushProjectFolders(root)
		if !errors.Is(err, errRushNotPnpm) {
			t.Errorf("err = %v, want errRushNotPnpm", err)
		}
	})

	t.Run("commented-out pnpmVersion does not satisfy the pnpm gate", func(t *testing.T) {
		root := writeRushRepo(t, map[string]string{
			rushJSONFile: `{ /* "pnpmVersion": "7.0.0", */ "npmVersion": "9.0.0" }`,
		})
		_, err := rushProjectFolders(root)
		if !errors.Is(err, errRushNotPnpm) {
			t.Errorf("err = %v, want errRushNotPnpm (commented pnpmVersion must not count)", err)
		}
	})

	t.Run("subspaces enabled is errRushSubspaces", func(t *testing.T) {
		root := writeRushRepo(t, map[string]string{
			rushJSONFile:        rushJSONPnpm,
			rushSubspacesConfig: `{"subspacesEnabled": true}`,
		})
		_, err := rushProjectFolders(root)
		if !errors.Is(err, errRushSubspaces) {
			t.Errorf("err = %v, want errRushSubspaces", err)
		}
	})

	// Regression for the customer fix: a subspaces.json that exists but has
	// subspacesEnabled:false must NOT skip the repo — the monorepo lockfile is
	// still authoritative, so the projects resolve normally.
	t.Run("subspaces present but disabled is scanned", func(t *testing.T) {
		root := writeRushRepo(t, map[string]string{
			rushJSONFile:        rushJSONPnpm,
			rushSubspacesConfig: `{"subspacesEnabled": false, "subspaceNames": []}`,
		})
		folders, err := rushProjectFolders(root)
		if err != nil {
			t.Fatalf("disabled subspaces must not error, got: %v", err)
		}
		if len(folders) != 2 {
			t.Errorf("want 2 project folders, got %v", folders)
		}
	})

	t.Run("missing rush.json errors", func(t *testing.T) {
		_, err := rushProjectFolders(t.TempDir())
		if err == nil {
			t.Error("expected an error reading a missing rush.json")
		}
		if errors.Is(err, errRushNotPnpm) || errors.Is(err, errRushSubspaces) {
			t.Errorf("a read failure must not masquerade as a skip sentinel: %v", err)
		}
	})
}

func TestIsRushRoot(t *testing.T) {
	withRush := writeRushRepo(t, map[string]string{rushJSONFile: `{}`})
	if !isRushRoot(withRush) {
		t.Error("dir containing rush.json should be a Rush root")
	}
	if isRushRoot(t.TempDir()) {
		t.Error("dir without rush.json should not be a Rush root")
	}
}

func TestWorkspaceYAML(t *testing.T) {
	got := string(workspaceYAML([]string{"apps/app-a", "libs/lib-b"}))
	want := "packages:\n  - ../../apps/app-a\n  - ../../libs/lib-b\n"
	if got != want {
		t.Errorf("workspaceYAML mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// stageRushFiles is the set of files a stageRushWorkspace happy path needs: a
// monorepo lockfile plus one package.json per project folder.
func stageRushFiles() map[string]string {
	return map[string]string{
		rushJSONFile:                    rushJSONPnpm,
		rushLockfilePath:                "lockfileVersion: '6.0'\n",
		"apps/app-a/" + packageJSONFile: `{"name":"@x/app-a","version":"1.0.0"}`,
		"libs/lib-b/" + packageJSONFile: `{"name":"@x/lib-b","version":"1.0.0"}`,
	}
}

func TestStageRushWorkspace_HappyPath(t *testing.T) {
	root := writeRushRepo(t, stageRushFiles())

	runDir, scanRoot, skipped, cleanup, err := stageRushWorkspace(root, []string{"apps/app-a", "libs/lib-b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(cleanup)

	if len(skipped) != 0 {
		t.Errorf("no projects should be skipped, got %v", skipped)
	}

	// runDir is <tmp>/common/temp and holds the lockfile, synthesized
	// workspace manifest, and the aggregate "." importer package.json.
	if filepath.Base(filepath.Dir(runDir)) != "common" || filepath.Base(runDir) != "temp" {
		t.Errorf("runDir should be common/temp, got %q", runDir)
	}
	for _, name := range []string{pnpmLockFile, "pnpm-workspace.yaml", packageJSONFile} {
		if !fileExists(filepath.Join(runDir, name)) {
			t.Errorf("expected staged file %q under runDir", name)
		}
	}

	// Each project's package.json is mirrored under scanRoot at its original
	// relative path so the ../../ importer paths resolve.
	for _, pf := range []string{"apps/app-a", "libs/lib-b"} {
		if !fileExists(filepath.Join(scanRoot, filepath.FromSlash(pf), packageJSONFile)) {
			t.Errorf("expected mirrored package.json for %q under scanRoot", pf)
		}
	}

	// The synthesized workspace manifest lists every staged project.
	ws, readErr := os.ReadFile(filepath.Join(runDir, "pnpm-workspace.yaml"))
	if readErr != nil {
		t.Fatalf("reading staged pnpm-workspace.yaml: %v", readErr)
	}
	for _, want := range []string{"../../apps/app-a", "../../libs/lib-b"} {
		if !strings.Contains(string(ws), want) {
			t.Errorf("pnpm-workspace.yaml missing %q;\n%s", want, ws)
		}
	}

	// cleanup tears the whole tmp tree down.
	cleanup()
	if _, statErr := os.Stat(scanRoot); !os.IsNotExist(statErr) {
		t.Errorf("cleanup should remove the staging tree, stat err = %v", statErr)
	}
}

func TestStageRushWorkspace_MissingProjectSkippedNotFatal(t *testing.T) {
	root := writeRushRepo(t, stageRushFiles())

	_, _, skipped, cleanup, err := stageRushWorkspace(root, []string{"apps/app-a", "libs/lib-b", "apps/ghost"})
	if err != nil {
		t.Fatalf("a stale project folder must not be fatal, got: %v", err)
	}
	t.Cleanup(cleanup)

	if len(skipped) != 1 || skipped[0] != "apps/ghost" {
		t.Errorf("skipped = %v, want [apps/ghost]", skipped)
	}
}

// stageErr runs stageRushWorkspace for the failure-path tests, which only care
// about the returned error (a failed stage returns a nil cleanup).
func stageErr(root string, folders []string) error {
	_, _, _, _, err := stageRushWorkspace(root, folders) //nolint:dogsled // error-path tests want only err
	return err
}

func TestStageRushWorkspace_ZeroReadableProjectsIsError(t *testing.T) {
	root := writeRushRepo(t, map[string]string{
		rushJSONFile:     rushJSONPnpm,
		rushLockfilePath: "lockfileVersion: '6.0'\n",
	})
	if err := stageErr(root, []string{"apps/app-a"}); err == nil {
		t.Error("a workspace with no readable package.json should error")
	}
}

func TestStageRushWorkspace_MissingLockfileIsError(t *testing.T) {
	root := writeRushRepo(t, map[string]string{
		rushJSONFile:                    rushJSONPnpm,
		"apps/app-a/" + packageJSONFile: `{"name":"@x/app-a","version":"1.0.0"}`,
	})
	if err := stageErr(root, []string{"apps/app-a"}); err == nil {
		t.Error("a missing Rush lockfile should error")
	}
}

func TestRushTargets_HappyPath(t *testing.T) {
	root := writeRushRepo(t, stageRushFiles())

	targets, err := rushTargets(context.Background(), logger.Nop(), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(targets))
	}
	tgt := targets[0]
	t.Cleanup(tgt.cleanup)

	if tgt.setupErr != nil {
		t.Errorf("happy path target should carry no setupErr, got %v", tgt.setupErr)
	}
	if tgt.cmdDir == "" || tgt.manifestBaseDir == "" {
		t.Errorf("target should have cmdDir and manifestBaseDir set, got %+v", tgt)
	}
	// excludeDir drops the synthetic rush-common aggregate importer.
	if tgt.excludeDir != tgt.cmdDir {
		t.Errorf("excludeDir should equal the common/temp runDir, got %q vs %q", tgt.excludeDir, tgt.cmdDir)
	}
	if !contains(tgt.processedFiles, rushJSONFile) {
		t.Errorf("processedFiles should include rush.json, got %v", tgt.processedFiles)
	}
}

func TestRushTargets_NonPnpmSkipped(t *testing.T) {
	root := writeRushRepo(t, map[string]string{
		rushJSONFile: `{ "npmVersion": "9.0.0", "projects": [] }`,
	})
	targets, err := rushTargets(context.Background(), logger.Nop(), root)
	if err != nil {
		t.Fatalf("skip should not error, got %v", err)
	}
	if targets != nil {
		t.Errorf("non-pnpm Rush repo should be skipped, got %d targets", len(targets))
	}
}

func TestRushTargets_SubspacesEnabledSkipped(t *testing.T) {
	files := stageRushFiles()
	files[rushSubspacesConfig] = `{"subspacesEnabled": true}`
	root := writeRushRepo(t, files)

	targets, err := rushTargets(context.Background(), logger.Nop(), root)
	if err != nil {
		t.Fatalf("skip should not error, got %v", err)
	}
	if targets != nil {
		t.Errorf("subspaces-enabled repo should be skipped, got %d targets", len(targets))
	}
}

// Regression for the customer fix at the adapter boundary: a disabled
// subspaces.json must produce a real, runnable target instead of a skip.
func TestRushTargets_SubspacesDisabledStaged(t *testing.T) {
	files := stageRushFiles()
	files[rushSubspacesConfig] = `{"subspacesEnabled": false}`
	root := writeRushRepo(t, files)

	targets, err := rushTargets(context.Background(), logger.Nop(), root)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("disabled subspaces must be scanned; want 1 target, got %d", len(targets))
	}
	t.Cleanup(targets[0].cleanup)
	if targets[0].setupErr != nil {
		t.Errorf("target should be runnable, got setupErr %v", targets[0].setupErr)
	}
}

func TestRushTargets_UnreadableRushJSONSurfacesErrTarget(t *testing.T) {
	// rush.json is a directory, so os.ReadFile fails — neither sentinel
	// matches, so rushTargets must surface a single error target rather than
	// silently skipping.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, rushJSONFile), 0o750); err != nil {
		t.Fatalf("staging unreadable rush.json: %v", err)
	}
	targets, err := rushTargets(context.Background(), logger.Nop(), root)
	if err != nil {
		t.Fatalf("rushTargets should return the error as a target, not fail: %v", err)
	}
	if len(targets) != 1 || targets[0].setupErr == nil {
		t.Fatalf("want one target carrying a setupErr, got %+v", targets)
	}
	t.Cleanup(targets[0].cleanup)
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
