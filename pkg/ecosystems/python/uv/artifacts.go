package uv

import (
	"regexp"
	"strings"
)

// pythonArtifact is one published file of a Python package: an sdist or a
// wheel.
type pythonArtifact struct {
	Filename string
	URL      string
	// Hashes maps an algorithm name, in any spelling
	// componentmetadata.CanonicalAlgorithm accepts, to its hex digest.
	Hashes map[string]string
}

var universalWheel = regexp.MustCompile(`(?i)-none-any\.whl$`)

// selectPythonArtifact applies poetry's rule (snyk-poetry-lockfile-parser
// lib/component-metadata-labels.ts, selectArtifact) for choosing the one
// artifact a node's labels describe, when the source lists every published
// file of a release: the universal wheel, otherwise the sdist. With only
// platform-specific wheels the target platform is unknown, so nothing is
// selected rather than guessed.
//
// It is used only where the installed file is unknown, as in a lockfile or
// export.
func selectPythonArtifact(files []pythonArtifact) (pythonArtifact, bool) {
	// As in poetry's selectArtifact: a single published file, or a source
	// pinned to one artifact, is unambiguous, so it is used whatever its
	// platform.
	if len(files) == 1 {
		return files[0], true
	}
	for _, f := range files {
		if universalWheel.MatchString(f.Filename) {
			return f, true
		}
	}
	for _, f := range files {
		lower := strings.ToLower(f.Filename)
		if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".zip") {
			return f, true
		}
	}
	return pythonArtifact{}, false
}
