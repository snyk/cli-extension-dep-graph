//go:build integration && gradle
// +build integration,gradle

package gradle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver/v3"
)

// fixtureMetadataFile is the conventional name of the per-fixture metadata
// file. Loaded from <fixture-dir>/<fixtureMetadataFile> when present.
const fixtureMetadataFile = "metadata.json"

// FixtureMetadata describes optional per-fixture constraints used to gate
// integration test execution against the Gradle / JDK runtime in use. Empty
// or missing fields are treated as "applies to all supported runtimes".
type FixtureMetadata struct {
	// Gradle is a semver constraint that the runtime Gradle version must
	// satisfy for the fixture to run. Uses Masterminds/semver/v3 syntax
	// (e.g. ">=7", ">=6, <9", "7.x"). Missing means: any Gradle version.
	Gradle string `json:"gradle,omitempty"`
	// JDK is a semver constraint applied to the runtime JDK major version.
	// Missing means: any JDK version.
	JDK string `json:"jdk,omitempty"`
	// Reason is a human-readable note that surfaces in skip messages when a
	// constraint excludes a particular runtime (e.g. "guava 32 POM uses a
	// metadata extension Gradle 6 cannot parse").
	Reason string `json:"reason,omitempty"`
}

// loadFixtureMetadata reads <fixtureDir>/metadata.json into a FixtureMetadata.
// A missing file is not an error: it returns the zero value, which means the
// fixture has no constraints.
func loadFixtureMetadata(fixtureDir string) (FixtureMetadata, error) {
	path := filepath.Join(fixtureDir, fixtureMetadataFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FixtureMetadata{}, nil
		}
		return FixtureMetadata{}, fmt.Errorf("read fixture metadata %s: %w", path, err)
	}

	var meta FixtureMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return FixtureMetadata{}, fmt.Errorf("parse fixture metadata %s: %w", path, err)
	}
	return meta, nil
}

// skipReason returns a non-empty string explaining why the fixture should be
// skipped against the given runtime versions, or "" if it applies. Constraint
// parse errors are propagated so a typo in metadata fails loudly rather than
// silently letting cases run.
func (m FixtureMetadata) skipReason(gradleVersion, jdkVersion *semver.Version) (string, error) {
	if m.Gradle != "" {
		ok, err := matchesConstraint(gradleVersion, m.Gradle)
		if err != nil {
			return "", fmt.Errorf("invalid gradle constraint %q: %w", m.Gradle, err)
		}
		if !ok {
			return formatSkipReason("gradle", m.Gradle, gradleVersion, m.Reason), nil
		}
	}
	if m.JDK != "" {
		ok, err := matchesConstraint(jdkVersion, m.JDK)
		if err != nil {
			return "", fmt.Errorf("invalid jdk constraint %q: %w", m.JDK, err)
		}
		if !ok {
			return formatSkipReason("jdk", m.JDK, jdkVersion, m.Reason), nil
		}
	}
	return "", nil
}

// matchesConstraint parses constraint and reports whether version satisfies it.
func matchesConstraint(version *semver.Version, constraint string) (bool, error) {
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}
	return c.Check(version), nil
}

func formatSkipReason(kind, constraint string, actual *semver.Version, reason string) string {
	base := fmt.Sprintf("requires %s %s; running on %s", kind, constraint, actual.String())
	if reason != "" {
		base += " (" + reason + ")"
	}
	return base
}
