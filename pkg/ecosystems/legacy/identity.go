package legacy

import (
	"path"
	"strings"
)

// shouldSuppressTargetFileFromPlugin reports whether the legacy CLI's plugin for the
// given project type would have left plugin.targetFile unset, in which case downstream
// consumers treat that absence as a signal when constructing API payloads — we have to
// suppress emission to preserve parity.
func shouldSuppressTargetFileFromPlugin(projectType, file string, isWorkspace bool) bool {
	switch projectType {
	case "pip":
		_, fileName := path.Split(file)
		// snyk-python-plugin sets targetFile for Pipfile and setup.py, but not for requirements.txt
		return strings.HasSuffix(fileName, "requirements.txt")
	case "gradle":
		_, fileName := path.Split(file)
		// snyk-gradle-plugin sets targetFile for build.gradle.kts but not for build.gradle
		return !strings.HasSuffix(fileName, "build.gradle.kts")
	case "poetry", "gomodules", "golangdep", "nuget", "paket", "composer", "cocoapods", "hex", "swift":
		// These plugins set relative path to provided targetFile
		return false
	case "npm", "yarn", "pnpm":
		// These plugins set targetFile only inside a workspace
		return !isWorkspace
	case "maven", "sbt", "rubygems":
		// These plugins do not set plugin.targetFile
		return true
	}
	// Unknown project types: default to suppression
	return true
}
