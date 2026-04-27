package legacy

import (
	"path"
	"strings"
)

// getProjectTargetFileBasedOnType determines if a plugin sets targetFile based on package manager type.
func getProjectTargetFileBasedOnType(projectType, file string, isWorkspace bool) *string {
	switch projectType {
	case "pip":
		_, fileName := path.Split(file)
		// snyk-python-plugin sets targetFile for Pipfile and setup.py, but not for requirements.txt
		if strings.HasSuffix(fileName, "requirements.txt") {
			return nil
		}
		return &file
	case "gradle":
		_, fileName := path.Split(file)
		// snyk-gradle-plugin sets targetFile for build.gradle.kts but not for build.gradle
		if strings.HasSuffix(fileName, "build.gradle.kts") {
			return &file
		}
		return nil
	case "poetry", "gomodules", "golangdep", "nuget", "paket", "composer", "cocoapods", "hex", "swift":
		// These plugins set relative path to provided targetFile
		return &file
	case "npm", "yarn", "pnpm":
		if isWorkspace {
			return &file
		}
		return nil
	case "maven", "sbt", "rubygems":
		// These plugins do not set plugin.targetFile
		return nil
	}
	return nil
}
