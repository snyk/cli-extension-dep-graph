package uv

import (
	"github.com/rs/zerolog"
	scaplugin "github.com/snyk/cli-extension-dep-graph/pkg/sca_plugin"
)

type Plugin struct {
	client Client
}

func NewUvPlugin(client Client) Plugin {
	return Plugin{
		client: client,
	}
}

func (p Plugin) BuildFindingsFromDir(inputDir string, _ scaplugin.Options, logger *zerolog.Logger) ([]scaplugin.Finding, error) {
	if !p.client.ShouldExportSBOM(inputDir, logger) {
		return []scaplugin.Finding{}, nil
	}

	finding, err := p.client.ExportSBOM(inputDir)
	if err != nil {
		//nolint:wrapcheck // Error is already wrapped with error catalog error from ExportSBOM
		return nil, err
	}
	return []scaplugin.Finding{*finding}, nil
}
