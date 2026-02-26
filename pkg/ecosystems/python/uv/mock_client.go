package uv

import (
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

type MockClient struct {
	CalledDirs []string
	ReturnErr  error
	ErrorDirs  map[string]error
}

func (m *MockClient) ExportSBOM(inputDir string, _ *ecosystems.SCAPluginOptions) (SBOM, error) {
	m.CalledDirs = append(m.CalledDirs, inputDir)

	if m.ErrorDirs != nil {
		if err, exists := m.ErrorDirs[inputDir]; exists {
			return nil, err
		}
	}

	if m.ReturnErr != nil {
		return nil, m.ReturnErr
	}

	sbom := `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"mock-project","version":"1.0.0"}}}`
	return SBOM(sbom), nil
}

var _ Client = (*MockClient)(nil)
