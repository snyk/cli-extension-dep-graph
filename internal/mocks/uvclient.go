package mocks

import "github.com/rs/zerolog"

// MockUVClient is a mock implementation of UVClient for testing
type MockUVClient struct {
	ExportSBOMFunc       func(inputDir string) ([]byte, error)
	ShouldExportSBOMFunc func(inputDir string, logger *zerolog.Logger) bool
}

func (m *MockUVClient) ExportSBOM(inputDir string) ([]byte, error) {
	if m.ExportSBOMFunc != nil {
		return m.ExportSBOMFunc(inputDir)
	}
	return []byte(`{"mock":"sbom"}`), nil
}

func (m *MockUVClient) ShouldExportSBOM(inputDir string, logger *zerolog.Logger) bool {
	if m.ShouldExportSBOMFunc != nil {
		return m.ShouldExportSBOMFunc(inputDir, logger)
	}
	return true
}
