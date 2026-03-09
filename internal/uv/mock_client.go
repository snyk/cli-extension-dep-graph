package uv

import (
	"github.com/snyk/cli-extension-dep-graph/pkg/scaplugin"
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

	sbom := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"serialNumber": "urn:uuid:d9b838b1-8d37-4399-9604-44086160b08b",
		"metadata": {
			"timestamp": "2026-03-16T16:19:32.146360000Z",
			"tools": [
				{
					"vendor": "Astral Software Inc.",
					"name": "uv",
					"version": "0.10.9"
				}
			],
			"component": {
				"type": "library",
				"bom-ref": "mock-project-1@1.0.0",
				"name": "mock-project",
				"version": "1.0.0",
				"properties": [
					{
						"name": "uv:package:is_project_root",
						"value": "true"
					}
				]
			}
		},
		"components": [
			{
				"type": "library",
				"bom-ref": "django-2@3.1",
				"name": "django",
				"version": "3.1",
				"purl": "pkg:pypi/django@3.1"
			},
			{
				"type": "library",
				"bom-ref": "idna-3@3.6",
				"name": "idna",
				"version": "3.6",
				"purl": "pkg:pypi/idna@3.6"
			}
		],
		"dependencies": [
			{
				"ref": "mock-project-1@1.0.0",
				"dependsOn": ["django-2@3.1", "idna-3@3.6"]
			},
			{
				"ref": "django-2@3.1",
				"dependsOn": []
			},
			{
				"ref": "idna-3@3.6",
				"dependsOn": []
			}
		]
	}`
	return Sbom(sbom), nil
}

var _ Client = (*MockClient)(nil)
