package mocks

import (
	"github.com/rs/zerolog"

	"github.com/snyk/cli-extension-dep-graph/internal/uv"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
)

// MockUVClient is a mock implementation of UVClient for testing
type MockUVClient struct {
	ExportSBOMFunc       func(inputDir string) (*scaplugin.Finding, error)
	ShouldExportSBOMFunc func(inputDir string, logger *zerolog.Logger) bool
}

func (m *MockUVClient) ExportSBOM(inputDir string) (*scaplugin.Finding, error) {
	if m.ExportSBOMFunc != nil {
		return m.ExportSBOMFunc(inputDir)
	}
	return &scaplugin.Finding{
		Sbom:           []byte(`{"mock":"sbom"}`),
		TargetFile:     "",
		FilesProcessed: []string{},
	}, nil
}

func (m *MockUVClient) ShouldExportSBOM(inputDir string, logger *zerolog.Logger) bool {
	if m.ShouldExportSBOMFunc != nil {
		return m.ShouldExportSBOMFunc(inputDir, logger)
	}
	return true
}

var _ uv.Client = (*MockUVClient)(nil)
