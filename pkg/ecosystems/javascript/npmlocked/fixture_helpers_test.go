//go:build integration && npm
// +build integration,npm

package npmlocked_test

// fixture_helpers_test.go holds the helpers shared by the integration test
// suites that walk testdata/legacy-fixtures/ (smoke + divergence-comparison).
//
// Compatibility detection is derived from each fixture's lockfileVersion
// field; the host npm version is queried once via `npm --version` and cached.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/semver"
)

const legacyFixturesRoot = "testdata/legacy-fixtures"

// lockfileShape is the minimum we need from a lockfile to decide compatibility.
type lockfileShape struct {
	LockfileVersion int `json:"lockfileVersion"`
}

// legacyFixture identifies one imported fixture under testdata/legacy-fixtures/.
type legacyFixture struct {
	// Category is the subdir under legacy-fixtures (general, v2, aliases, …).
	Category string
	// Name is the fixture directory's basename.
	Name string
	// Dir is the fixture's absolute path (Go test cwd is the package dir).
	Dir string
	// LockfileVersion is the integer parsed from package-lock.json.
	LockfileVersion int
	// HasLegacyExpected is true iff legacy-expected.json is present.
	HasLegacyExpected bool
}

// ID is the "category/name" identifier used as the t.Run subtest name.
func (f legacyFixture) ID() string {
	return f.Category + "/" + f.Name
}

// MinNpmVersion returns the lowest npm semver string that can read this
// fixture's lockfile. Lockfile v1 is npm 6 (our floor); v2/v3 require npm 7+.
func (f legacyFixture) MinNpmVersion() string {
	if f.LockfileVersion >= 2 {
		return "v7.0.0"
	}
	return "v6.0.0"
}

// discoverLegacyFixtures walks legacyFixturesRoot and returns every fixture
// with both a package.json and a package-lock.json.
func discoverLegacyFixtures(t *testing.T) []legacyFixture {
	t.Helper()

	categories, err := os.ReadDir(legacyFixturesRoot)
	if err != nil {
		t.Fatalf("reading legacy fixtures root: %v", err)
	}

	var out []legacyFixture

	for _, cat := range categories {
		if !cat.IsDir() {
			continue
		}
		catDir := filepath.Join(legacyFixturesRoot, cat.Name())

		entries, err := os.ReadDir(catDir)
		if err != nil {
			t.Fatalf("reading category %s: %v", cat.Name(), err)
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			fxDir := filepath.Join(catDir, entry.Name())

			lockPath := filepath.Join(fxDir, "package-lock.json")
			pkgPath := filepath.Join(fxDir, "package.json")
			if _, err := os.Stat(lockPath); err != nil {
				continue
			}
			if _, err := os.Stat(pkgPath); err != nil {
				continue
			}

			ver := readLockfileVersion(t, lockPath)

			_, legacyErr := os.Stat(filepath.Join(fxDir, "legacy-expected.json"))

			out = append(out, legacyFixture{
				Category:          cat.Name(),
				Name:              entry.Name(),
				Dir:               fxDir,
				LockfileVersion:   ver,
				HasLegacyExpected: legacyErr == nil,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// readLockfileVersion parses just the lockfileVersion field from a
// package-lock.json. Returns 0 if the field is missing or unreadable; the
// caller can decide whether 0 is treated as "unknown".
func readLockfileVersion(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var shape lockfileShape
	if err := json.Unmarshal(data, &shape); err != nil {
		t.Logf("warning: %s does not parse as JSON (%v); treating lockfileVersion as 0", path, err)
		return 0
	}
	return shape.LockfileVersion
}

var (
	hostNpmVerOnce sync.Once
	hostNpmVerStr  string
	hostNpmVerErr  error
)

// hostNpmVersion returns the canonical Go semver string for the npm on PATH,
// or an error if npm is absent or its --version output is unparseable. Cached
// for the lifetime of the test process.
func hostNpmVersion(t *testing.T) (string, error) {
	t.Helper()

	hostNpmVerOnce.Do(func() {
		path, err := exec.LookPath("npm")
		if err != nil {
			hostNpmVerErr = fmt.Errorf("npm not in PATH: %w", err)
			return
		}
		out, err := exec.Command(path, "--version").Output()
		if err != nil {
			hostNpmVerErr = fmt.Errorf("npm --version failed: %w", err)
			return
		}
		hostNpmVerStr, hostNpmVerErr = parseTestNpmVersion(strings.TrimSpace(string(out)))
	})

	return hostNpmVerStr, hostNpmVerErr
}

var testNpmVerRe = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

func parseTestNpmVersion(raw string) (string, error) {
	m := testNpmVerRe.FindStringSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("could not parse npm version from %q", raw)
	}
	return "v" + m[1] + "." + m[2] + "." + m[3], nil
}

// requireFixtureCompat skips the current subtest if the host npm version
// cannot handle the fixture's lockfile. Use at the top of every
// per-fixture subtest body.
func requireFixtureCompat(t *testing.T, fx legacyFixture) {
	t.Helper()

	hostVer, err := hostNpmVersion(t)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	minVer := fx.MinNpmVersion()
	if semver.Compare(hostVer, minVer) < 0 {
		t.Skipf("skipping: lockfileVersion %d needs npm %s, host has %s",
			fx.LockfileVersion, minVer, hostVer)
	}
}
