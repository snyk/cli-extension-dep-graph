package uv

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
	clierrors "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

const (
	UvLockFileName          = "uv.lock"
	RequirementsTxtFileName = "requirements.txt"
	PyprojectTomlFileName   = "pyproject.toml"
	UvWorkspacePathProperty = "uv:workspace:path"
)

type Client interface {
	ExportSBOM(inputDir string, opts *scaplugin.Options) (*scaplugin.Finding, error)
}

type client struct {
	uvBinary string
	executor cmdExecutor
}

var _ Client = (*client)(nil)

func NewUvClient() Client {
	return NewUvClientWithPath("uv")
}

func NewUvClientWithPath(uvBinary string) Client {
	return NewUvClientWithExecutor(uvBinary, &defaultCmdExecutor{})
}

// NewUvClientWithExecutor creates a new uv client with a custom executor for testing.
func NewUvClientWithExecutor(uvBinary string, executor cmdExecutor) Client {
	return &client{
		uvBinary: uvBinary,
		executor: executor,
	}
}

// exportSBOM exports an SBOM in CycloneDX format using uv.
func (c client) ExportSBOM(inputDir string, opts *scaplugin.Options) (*scaplugin.Finding, error) {
	args := []string{"export", "--format", "cyclonedx1.5", "--frozen", "--preview"}
	if opts.AllProjects {
		args = append(args, "--all-packages")
	}
	if !opts.Dev {
		args = append(args, "--no-dev")
	}
	output, err := c.executor.Execute(c.uvBinary, inputDir, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute uv export: %w", err)
	}

	sbom, err := parseAndValidateSBOM(output)
	if err != nil {
		return nil, err
	}

	metadata := extractMetadata(sbom)
	workspacePackages := extractWorkspacePackages(sbom)

	// TODO(uv): uncomment when we are able to pass these to the CLI correctly. Currently the
	// `--exclude` flag does not accept paths, it only accepts file or dir names, which does not
	// work for our use case.
	// fileExclusions := buildFileExclusions(workspacePackages)
	fileExclusions := []string{}

	return &scaplugin.Finding{
		Sbom:                 output,
		Metadata:             *metadata,
		FileExclusions:       fileExclusions,
		NormalisedTargetFile: filepath.Join(inputDir, PyprojectTomlFileName),
		WorkspacePackages:    workspacePackages,
	}, nil
}

// Builds a list of files to exclude from scanning in other plugins.
func buildFileExclusions(workspacePackages []scaplugin.WorkspacePackage) []string {
	exclusions := []string{}
	for _, pkg := range workspacePackages {
		exclusions = append(exclusions,
			filepath.Join(pkg.Path, PyprojectTomlFileName),
			filepath.Join(pkg.Path, RequirementsTxtFileName),
		)
	}
	return exclusions
}

// Minimal representation of a CycloneDX SBOM.
type cycloneDXSBOM struct {
	Metadata struct {
		Component *struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
	Components []cycloneDXComponent `json:"components"`
}

// Minimal representation of a CycloneDX component.
type cycloneDXComponent struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

// Parses and validates the SBOM JSON.
// Returns the parsed struct or an error if parsing or validation fails.
func parseAndValidateSBOM(sbomData []byte) (*cycloneDXSBOM, error) {
	var sbom cycloneDXSBOM

	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return nil, ecosystems.NewUnprocessableFileError(
			fmt.Sprintf("Failed to parse SBOM JSON: %v", err),
			snyk_errors.WithCause(err),
		)
	}

	if sbom.Metadata.Component == nil {
		return nil, ecosystems.NewUnprocessableFileError(
			"SBOM missing root component at metadata.component - uv project may be missing a root package",
		)
	}

	if sbom.Metadata.Component.Name == "" {
		return nil, ecosystems.NewUnprocessableFileError(
			"SBOM root component missing name - invalid SBOM structure",
		)
	}

	return &sbom, nil
}

func extractMetadata(sbom *cycloneDXSBOM) *scaplugin.Metadata {
	return &scaplugin.Metadata{
		PackageManager: "pip",
		Name:           sbom.Metadata.Component.Name,
		Version:        sbom.Metadata.Component.Version,
	}
}

func extractWorkspacePackages(sbom *cycloneDXSBOM) []scaplugin.WorkspacePackage {
	var workspacePackages []scaplugin.WorkspacePackage
	for _, component := range sbom.Components {
		for _, prop := range component.Properties {
			if prop.Name == UvWorkspacePathProperty {
				workspacePackages = append(workspacePackages, scaplugin.WorkspacePackage{
					Name:    component.Name,
					Version: component.Version,
					Path:    prop.Value,
				})
				break // Should only have one workspace property per component
			}
		}
	}

	return workspacePackages
}

// cmdExecutor interface for executing commands mockable.
type cmdExecutor interface {
	Execute(binary, dir string, args ...string) ([]byte, error)
}

// defaultCmdExecutor is the real implementation of cmdExecutor.
type defaultCmdExecutor struct{}

func (e *defaultCmdExecutor) Execute(binary, dir string, args ...string) ([]byte, error) {
	// Check if uv binary exists in PATH and resolve the full path
	resolvedBinary, err := exec.LookPath(binary)
	if err != nil {
		return nil, clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("%s binary not found in PATH", binary),
			snyk_errors.WithCause(err),
		)
	}

	//nolint:govet // Reassigning to err is fine
	if err := checkVersion(resolvedBinary); err != nil {
		return nil, err
	}

	cmd := exec.Command(resolvedBinary, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("failed to execute uv export command: %v\noutput: %s", err, string(output)),
			snyk_errors.WithCause(err),
		)
	}
	return output, nil
}

func checkVersion(binary string) error {
	cmd := exec.Command(binary, "--version")
	output, err := cmd.Output()
	if err != nil {
		return clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("failed to get %s version\noutput: %s", binary, string(output)),
			snyk_errors.WithCause(err),
		)
	}
	return parseAndValidateVersion(binary, string(output))
}

func parseAndValidateVersion(binary, versionOutput string) error {
	versionRe := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	matches := versionRe.FindStringSubmatch(versionOutput)
	// First element in matches is the full match, remainder are capture groups
	if len(matches) < 4 {
		return clierrors.NewGeneralSCAFailureError(
			fmt.Sprintf("unable to parse %s version from output: %s", binary, versionOutput),
		)
	}

	curVersion := Version{
		mustAtoi(matches[1]),
		mustAtoi(matches[2]),
		mustAtoi(matches[3]),
	}
	minVersion := Version{0, 9, 11} // Min version containing SBOM export functionality
	if compareVersions(curVersion, minVersion) >= 0 {
		return nil
	}

	return clierrors.NewGeneralSCAFailureError(
		fmt.Sprintf(
			"%s version %s is not supported. Minimum required version is %s",
			binary,
			formatVersion(curVersion),
			formatVersion(minVersion),
		),
	)
}

type Version = [3]int

// Compares two semantic versions.
// Returns -1 if v1 < v2, 0 if v1 == v2, and 1 if v1 > v2.
func compareVersions(v1, v2 Version) int {
	for i := range len(v1) {
		if v1[i] < v2[i] {
			return -1
		}
		if v1[i] > v2[i] {
			return 1
		}
	}
	return 0
}

func mustAtoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("failed to convert %q to int: %v", s, err))
	}
	return i
}

func formatVersion(version Version) string {
	versionStrs := []string{}
	for _, v := range version {
		versionStrs = append(versionStrs, strconv.Itoa(v))
	}
	return strings.Join(versionStrs, ".")
}
