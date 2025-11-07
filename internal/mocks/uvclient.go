package mocks

// MockUVClient is a mock implementation of UVClient for testing
type MockUVClient struct {
	ExportSBOMFunc func(inputDir string) ([]byte, error)
}

func (m *MockUVClient) ExportSBOM(inputDir string) ([]byte, error) {
	if m.ExportSBOMFunc != nil {
		return m.ExportSBOMFunc(inputDir)
	}
	return []byte(`{"mock":"sbom"}`), nil
}
