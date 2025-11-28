package mocks

import (
	"github.com/rs/zerolog"

	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
)

type MockUVClient struct {
	CalledDirs []string
	ReturnErr  error
}

func (m *MockUVClient) ExportSBOM(inputDir string, _ scaplugin.Options) (*scaplugin.Finding, error) {
	m.CalledDirs = append(m.CalledDirs, inputDir)
	if m.ReturnErr != nil {
		return nil, m.ReturnErr
	}
	return &scaplugin.Finding{
		Sbom: []byte(`{"mock":"sbom"}`),
		Metadata: scaplugin.Metadata{
			PackageManager: "pip",
			Name:           "mock-project",
			Version:        "1.0.0",
		},
		FileExclusions:       []string{},
		NormalisedTargetFile: "uv.lock",
	}, nil
}

func (m *MockUVClient) ShouldExportSBOM(_ string, _ *zerolog.Logger) bool {
	return true
}
