package nuget

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// slnxNode is one element of a `.slnx` solution. Projects can sit at the top
// level or inside solution folders nested to any depth, so folders recurse.
type slnxNode struct {
	Path     string     `xml:"Path,attr"`
	Projects []slnxNode `xml:"Project"`
	Folders  []slnxNode `xml:"Folder"`
}

// parseSlnx returns the project paths a `.slnx` solution references, exactly as
// the solution wrote them: relative to the solution file, and with either path
// separator.
//
// `.slnx` is the XML solution format introduced with Visual Studio 17.14 /
// .NET 9: a <Solution> holding <Project Path="..." /> elements, optionally
// grouped in <Folder> elements. Unlike the text `.sln` format, solution folders
// are their own element type, so every <Project> really is a project.
func parseSlnx(solutionPath string) ([]string, error) {
	contents, err := os.ReadFile(solutionPath)
	if err != nil {
		return nil, fmt.Errorf("reading solution file %s: %w", solutionPath, err)
	}

	var solution slnxNode
	if err := xml.Unmarshal(contents, &solution); err != nil {
		return nil, fmt.Errorf("parsing .slnx solution %s: %w", solutionPath, err)
	}

	return collectSlnxProjectPaths(solution), nil
}

// collectSlnxProjectPaths walks a solution's projects and folders depth-first.
// The order is stable but not document order: every project at one level comes
// before the projects nested in that level's folders, whatever order the two
// element types appeared in. Nothing downstream depends on the order.
func collectSlnxProjectPaths(node slnxNode) []string {
	var paths []string

	for _, project := range node.Projects {
		if project.Path != "" {
			paths = append(paths, project.Path)
		}
	}

	for _, folder := range node.Folders {
		paths = append(paths, collectSlnxProjectPaths(folder)...)
	}

	return paths
}

// isSlnxFile reports whether path names a `.slnx` solution.
//
// The text `.sln` format is deliberately not claimed here. Its project entries
// double as solution folders and as project types this resolver has nothing to
// say about, all keyed by GUID, and the legacy resolver already reads them —
// so `--file=*.sln` keeps going there.
func isSlnxFile(path string) bool {
	return strings.EqualFold(filepath.Ext(path), slnxExtension)
}

// solutionProjectDir turns a project path as written in a solution into a
// directory relative to the solution's own. Solution files use either separator
// whatever platform they are read on.
//
// A path written with a trailing separator names a folder rather than a project
// file: that is how an ASP.NET Website project is recorded, and it has no
// project file at all. Such a project can never have an assets file either, so
// in practice it sends the whole solution to the legacy resolver.
func solutionProjectDir(solutionDir, projectPath string) string {
	normalised := filepath.FromSlash(strings.ReplaceAll(projectPath, `\`, "/"))

	if strings.HasSuffix(normalised, string(filepath.Separator)) {
		return filepath.Join(solutionDir, normalised)
	}

	return filepath.Join(solutionDir, filepath.Dir(normalised))
}
