package uv

import (
	"encoding/json"
	"fmt"

	ecosystemerr "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
)

const (
	UvLockFileName          = "uv.lock"
	RequirementsTxtFileName = "requirements.txt"
	PyprojectTomlFileName   = "pyproject.toml"
	UvWorkspacePathProperty = "uv:workspace:path"
)

type Client interface {
	ExportSBOM(inputDir string, opts *ecosystems.SCAPluginOptions) (SBOM, error)
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
	return NewUvClientWithExecutor(uvBinary, &uvCmdExecutor{})
}

// NewUvClientWithExecutor creates a new uv client with a custom executor for testing.
func NewUvClientWithExecutor(uvBinary string, executor cmdExecutor) Client {
	return &client{
		uvBinary: uvBinary,
		executor: executor,
	}
}

type SBOM []byte

type WorkspacePackage struct {
	Name    string
	Version string
	Path    string // Relative path to the workspace package directory
}

// exportSBOM exports an SBOM in CycloneDX format using uv.
func (c client) ExportSBOM(inputDir string, opts *ecosystems.SCAPluginOptions) (SBOM, error) {
	args := []string{"export", "--format", "cyclonedx1.5", "--locked", "--preview"}
	if opts.Global.AllProjects {
		args = append(args, "--all-packages")
	}
	if !opts.Global.IncludeDev {
		args = append(args, "--no-dev")
	}
	output, err := c.executor.Execute(c.uvBinary, inputDir, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute uv export: %w", err)
	}

	return output, nil
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
func parseAndValidateSBOM(sbomData SBOM) (*cycloneDXSBOM, error) {
	var sbom cycloneDXSBOM

	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return nil, ecosystemerr.NewUnprocessableFileError(
			fmt.Sprintf("Failed to parse SBOM JSON: %v", err),
			snyk_errors.WithCause(err),
		)
	}

	if sbom.Metadata.Component == nil {
		return nil, ecosystemerr.NewUnprocessableFileError(
			"SBOM missing root component at metadata.component - uv project may be missing a root package",
		)
	}

	if sbom.Metadata.Component.Name == "" {
		return nil, ecosystemerr.NewUnprocessableFileError(
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

func extractWorkspacePackages(sbom *cycloneDXSBOM) []WorkspacePackage {
	var workspacePackages []WorkspacePackage
	for _, component := range sbom.Components {
		for _, prop := range component.Properties {
			if prop.Name == UvWorkspacePathProperty {
				workspacePackages = append(workspacePackages, WorkspacePackage{
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
