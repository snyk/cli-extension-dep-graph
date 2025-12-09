package uv

import (
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
)

type MockClient struct {
	CalledDirs []string
	ReturnErr  error
	ErrorDirs  map[string]error
}

func (m *MockClient) ExportSBOM(inputDir string, _ *scaplugin.Options) (Sbom, error) {
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
	return Sbom(sbom), nil
}

var _ Client = (*MockClient)(nil)
