//go:build integration && gradle
// +build integration,gradle

package gradle

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Masterminds/semver/v3"
)

// gradleVersionLine captures the first whitespace-separated token after the
// literal "Gradle" header in `gradle --version` output, e.g. "Gradle 8.10.2".
var gradleVersionLine = regexp.MustCompile(`(?m)^Gradle\s+([0-9][0-9A-Za-z.\-+]*)`)

// jdkVersionLine captures the version literal from a `java -version` line
// such as `openjdk version "17.0.10"` or `java version "1.8.0_372"`.
var jdkVersionLine = regexp.MustCompile(`version\s+"([^"]+)"`)

var (
	gradleRuntimeOnce    sync.Once
	gradleRuntimeVersion *semver.Version
	gradleRuntimeErr     error

	jdkRuntimeOnce    sync.Once
	jdkRuntimeVersion *semver.Version
	jdkRuntimeErr     error
)

// detectGradleVersion shells out to `gradle --version` and parses the result.
// It is exposed as a variable so tests can stub it out if needed.
var detectGradleVersion = func() (*semver.Version, error) {
	out, err := exec.Command("gradle", "--version").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("gradle --version failed: %w\n%s", err, out)
	}
	match := gradleVersionLine.FindStringSubmatch(string(out))
	if match == nil {
		return nil, fmt.Errorf("could not parse gradle version from output:\n%s", out)
	}
	return semver.NewVersion(match[1])
}

// detectJDKVersion shells out to `java -version` (which prints to stderr) and
// parses the result into a normalised major.minor.patch.
var detectJDKVersion = func() (*semver.Version, error) {
	out, err := exec.Command("java", "-version").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("java -version failed: %w\n%s", err, out)
	}
	match := jdkVersionLine.FindStringSubmatch(string(out))
	if match == nil {
		return nil, fmt.Errorf("could not parse jdk version from output:\n%s", out)
	}
	return parseJDKVersion(match[1])
}

// parseJDKVersion normalises legacy and modern JDK version strings into
// semver. It collapses the legacy "1.X.Y" scheme (Java 8 and earlier) onto
// the modern major version "X.Y", strips build identifiers (everything from
// the first '_' onward) and rejects strings that have no recognisable
// numeric prefix.
func parseJDKVersion(raw string) (*semver.Version, error) {
	cleaned := strings.SplitN(raw, "_", 2)[0]
	parts := strings.Split(cleaned, ".")
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("could not parse jdk version %q", raw)
	}

	if parts[0] == "1" && len(parts) >= 2 {
		// Legacy "1.X.Y" -> "X.Y.0". Java 8 prints "1.8.0_x".
		major := parts[1]
		minor := "0"
		if len(parts) >= 3 {
			minor = parts[2]
		}
		return semver.NewVersion(fmt.Sprintf("%s.%s.0", major, minor))
	}

	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	for _, part := range parts[:3] {
		if _, err := strconv.Atoi(part); err != nil {
			return nil, fmt.Errorf("non-numeric component in jdk version %q", raw)
		}
	}
	return semver.NewVersion(strings.Join(parts[:3], "."))
}

// gradleRuntime returns the major.minor.patch version of the gradle binary
// resolved from PATH. The lookup is performed once per test run.
func gradleRuntime() (*semver.Version, error) {
	gradleRuntimeOnce.Do(func() {
		gradleRuntimeVersion, gradleRuntimeErr = detectGradleVersion()
	})
	return gradleRuntimeVersion, gradleRuntimeErr
}

// jdkRuntime returns the major.minor.patch version of the JDK in use. The
// lookup is performed once per test run.
func jdkRuntime() (*semver.Version, error) {
	jdkRuntimeOnce.Do(func() {
		jdkRuntimeVersion, jdkRuntimeErr = detectJDKVersion()
	})
	return jdkRuntimeVersion, jdkRuntimeErr
}
