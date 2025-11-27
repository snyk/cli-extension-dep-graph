package mocks

import (
	"github.com/rs/zerolog"

	"github.com/snyk/cli-extension-dep-graph/internal/uv"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
)

// MockUVClient is a mock implementation of UVClient for testing
type MockUVClient struct {
	ExportSBOMFunc       func(inputDir string, opts scaplugin.Options) (*scaplugin.Finding, error)
	ShouldExportSBOMFunc func(inputDir string, logger *zerolog.Logger) bool
}

func (m *MockUVClient) ExportSBOM(inputDir string, opts scaplugin.Options) (*scaplugin.Finding, error) {
	if m.ExportSBOMFunc != nil {
		return m.ExportSBOMFunc(inputDir, opts)
	}
	return &scaplugin.Finding{
		Sbom: []byte(`{"mock":"sbom"}`),
		Metadata: scaplugin.Metadata{
			PackageManager: "pip",
			Name:           "mock-project",
			Version:        "0.0.0",
		},
		FileExclusions:       []string{},
		NormalisedTargetFile: uv.UvLockFileName,
	}, nil
}

func (m *MockUVClient) ShouldExportSBOM(inputDir string, logger *zerolog.Logger) bool {
	if m.ShouldExportSBOMFunc != nil {
		return m.ShouldExportSBOMFunc(inputDir, logger)
	}
	return true
}

var _ uv.Client = (*MockUVClient)(nil)
