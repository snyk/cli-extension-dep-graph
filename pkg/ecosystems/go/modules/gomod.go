package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	goModFile  = "go.mod"
	goWorkFile = "go.work"
)

// readModulePath parses a go.mod file and returns the value of its
// `module` directive. Used as an offline-safe fallback for the root
// module name before we have `go list` output to consult.
//
// The Go module file syntax for the module directive is one of:
//
//	module example.com/foo
//	module "example.com/foo"
//	module (
//	    example.com/foo
//	)
//
// We support the bare and single-line quoted forms; the block form is
// legal but vanishingly rare in real projects. If we can't find a
// recognisable module directive we return an empty string rather than
// an error — the caller will then fall back to the `go list` output.
func readModulePath(goModPath string) (string, error) {
	f, err := os.Open(goModPath)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", goModPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.HasPrefix(line, "module") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		if rest == "" || rest == "(" {
			// Block form: scan ahead for the first non-comment line.
			for scanner.Scan() {
				inner := strings.TrimSpace(scanner.Text())
				if inner == "" || strings.HasPrefix(inner, "//") {
					continue
				}
				if inner == ")" {
					break
				}
				return unquoteModulePath(inner), nil
			}
			return "", nil
		}
		return unquoteModulePath(rest), nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading %s: %w", goModPath, err)
	}
	return "", nil
}

// unquoteModulePath strips surrounding quotes (single or double) and
// any trailing line comment from a raw module-directive value.
func unquoteModulePath(s string) string {
	// Trim trailing comment.
	if i := strings.Index(s, "//"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			s = s[1 : len(s)-1]
		}
	}
	return s
}

// readWorkspaceDirs reads a go.work file and returns the directories
// of the `use` declarations, as paths relative to the workspace root.
// Each returned directory holds a go.mod that the workspace composes.
//
// We accept both forms documented in `go help work`:
//
//	use ./foo
//	use (
//	    ./foo
//	    ./bar
//	)
//
// Returns nil with no error if the file doesn't exist — go.work is
// optional and most projects don't have one.
func readWorkspaceDirs(goWorkPath string) ([]string, error) {
	f, err := os.Open(goWorkPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening %s: %w", goWorkPath, err)
	}
	defer f.Close()

	var dirs []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	inBlock := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if inBlock {
			if line == ")" {
				inBlock = false
				continue
			}
			dirs = append(dirs, cleanWorkspaceDir(line))
			continue
		}
		if !strings.HasPrefix(line, "use") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "use"))
		switch {
		case rest == "" || rest == "(":
			inBlock = true
		default:
			dirs = append(dirs, cleanWorkspaceDir(rest))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", goWorkPath, err)
	}
	return dirs, nil
}

// cleanWorkspaceDir strips quotes, comments, and normalises a workspace
// `use` directive entry into a relative filesystem path.
func cleanWorkspaceDir(s string) string {
	if i := strings.Index(s, "//"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return filepath.Clean(s)
}
