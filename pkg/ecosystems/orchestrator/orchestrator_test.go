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
					[]byte(`{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","targetFileFromPlugin":"package.json","target":{}}`)),
			},
			nil)

	results, err := LegacyFallback(ictx, *opts, nil)

	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "npm", results[0].ProjectDescriptor.Identity.Type)
}
