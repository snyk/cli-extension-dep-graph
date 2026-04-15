package orchestrator

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

func TestLegacyFallback_MapsProjectType(t *testing.T) {
	results, err := runLegacyFallback(t, `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","targetFileFromPlugin":"package.json","target":{}}`) //nolint:lll // This is fine.
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "npm", results[0].ProjectDescriptor.Identity.Type)
}

func TestLegacyFallback_MapsTargetFramework(t *testing.T) {
	results, err := runLegacyFallback(t, `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json","targetFileFromPlugin":"project.assets.json","target":{},"targetRuntime":"net6.0"}`) //nolint:lll // This is fine.
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "net6.0", *results[0].ProjectDescriptor.Identity.TargetRuntime)
}

func TestLegacyFallback_MapsTargetFile(t *testing.T) {
	tests := map[string]struct {
		body               string
		expectedTargetFile string
	}{
		"npm": {
			body: `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package-lock.json","target":{}}`,
		},
		"npm workspaces": {
			body:               `{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package-lock.json","target":{},"workspace":{}}`,
			expectedTargetFile: "package-lock.json",
		},
		"yarn": {
			body: `{"depGraph":{"pkgManager":{"name":"yarn"}},"normalisedTargetFile":"yarn.lock","target":{}}`,
		},
		"yarn workspaces": {
			body:               `{"depGraph":{"pkgManager":{"name":"yarn"}},"normalisedTargetFile":"yarn.lock","target":{},"workspace":{}}`,
			expectedTargetFile: "yarn.lock",
		},
		"pnpm": {
			body: `{"depGraph":{"pkgManager":{"name":"pnpm"}},"normalisedTargetFile":"pnpm.lock","target":{}}`,
		},
		"pnpm workspaces": {
			body:               `{"depGraph":{"pkgManager":{"name":"pnpm"}},"normalisedTargetFile":"pnpm.lock","target":{},"workspace":{}}`,
			expectedTargetFile: "pnpm.lock",
		},
		"pip requirements.txt": {
			body: `{"depGraph":{"pkgManager":{"name":"pip"}},"normalisedTargetFile":"requirements.txt","target":{}}`,
		},
		"pip pipfile": {
			body:               `{"depGraph":{"pkgManager":{"name":"pip"}},"normalisedTargetFile":"Pipfile","target":{}}`,
			expectedTargetFile: "Pipfile",
		},
		"pip setup.py": {
			body:               `{"depGraph":{"pkgManager":{"name":"pip"}},"normalisedTargetFile":"setup.py","target":{}}`,
			expectedTargetFile: "setup.py",
		},
		"gradle": {
			body: `{"depGraph":{"pkgManager":{"name":"gradle"}},"normalisedTargetFile":"build.gradle","target":{}}`,
		},
		"gradle build.gradle.kts": {
			body:               `{"depGraph":{"pkgManager":{"name":"gradle"}},"normalisedTargetFile":"build.gradle.kts","target":{}}`,
			expectedTargetFile: "build.gradle.kts",
		},
		"poetry": {
			body:               `{"depGraph":{"pkgManager":{"name":"poetry"}},"normalisedTargetFile":"poetry.lock","target":{}}`,
			expectedTargetFile: "poetry.lock",
		},
		"gomodules": {
			body:               `{"depGraph":{"pkgManager":{"name":"gomodules"}},"normalisedTargetFile":"go.mod","target":{}}`,
			expectedTargetFile: "go.mod",
		},
		"golangdep": {
			body:               `{"depGraph":{"pkgManager":{"name":"golangdep"}},"normalisedTargetFile":"Gopkg.lock","target":{}}`,
			expectedTargetFile: "Gopkg.lock",
		},
		"nuget": {
			body:               `{"depGraph":{"pkgManager":{"name":"nuget"}},"normalisedTargetFile":"project.assets.json","target":{}}`,
			expectedTargetFile: "project.assets.json",
		},
		"paket": {
			body:               `{"depGraph":{"pkgManager":{"name":"paket"}},"normalisedTargetFile":"paket.lock","target":{}}`,
			expectedTargetFile: "paket.lock",
		},
		"composer": {
			body:               `{"depGraph":{"pkgManager":{"name":"composer"}},"normalisedTargetFile":"composer.lock","target":{}}`,
			expectedTargetFile: "composer.lock",
		},
		"cocoapods": {
			body:               `{"depGraph":{"pkgManager":{"name":"cocoapods"}},"normalisedTargetFile":"Podfile.lock","target":{}}`,
			expectedTargetFile: "Podfile.lock",
		},
		"hex": {
			body:               `{"depGraph":{"pkgManager":{"name":"hex"}},"normalisedTargetFile":"mix.lock","target":{}}`,
			expectedTargetFile: "mix.lock",
		},
		"swift": {
			body:               `{"depGraph":{"pkgManager":{"name":"swift"}},"normalisedTargetFile":"Package.swift","target":{}}`,
			expectedTargetFile: "Package.swift",
		},
		"maven": {
			body: `{"depGraph":{"pkgManager":{"name":"maven"}},"normalisedTargetFile":"pom.xml","target":{}}`,
		},
		"sbt": {
			body: `{"depGraph":{"pkgManager":{"name":"sbt"}},"normalisedTargetFile":"build.sbt","target":{}}`,
		},
		"rubygems": {
			body: `{"depGraph":{"pkgManager":{"name":"rubygems"}},"normalisedTargetFile":"Gemfile.lock","target":{}}`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			results, err := runLegacyFallback(t, test.body)

			require.NoError(t, err)
			require.Len(t, results, 1)

			assert.Equal(t, test.expectedTargetFile, results[0].ProjectDescriptor.GetTargetFile())
		})
	}
}

func runLegacyFallback(t *testing.T, testBody string) ([]ecosystems.SCAResult, error) {
	t.Helper()

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	engine := gafmocks.NewMockEngine(ctrl)
	cfg := configuration.New()
	logger := zerolog.Nop()

	opts := ecosystems.NewPluginOptions()

	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return(
			[]workflow.Data{
				workflow.NewData(
					workflow.NewTypeIdentifier(legacyCLIWorkflowID, "application/text"),
					"application/text",
					[]byte(testBody)),
			},
			nil)

	return LegacyFallback(ictx, *opts, nil)
}
