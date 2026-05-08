package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalworkflow "github.com/snyk/cli-extension-dep-graph/internal/workflow"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/legacy"
	ecosystemslogger "github.com/snyk/cli-extension-dep-graph/pkg/ecosystems/logger"
	"github.com/snyk/cli-extension-dep-graph/pkg/identity"
)

func ptr[T any](v T) *T { return &v }

type fakePlugin struct {
	result *ecosystems.PluginResult
	err    error
}

func (f fakePlugin) GetName() string { return "fake" }

func (f fakePlugin) BuildDepGraphsFromDir(
	_ context.Context,
	_ ecosystemslogger.Logger,
	_ string,
	_ *ecosystems.SCAPluginOptions,
) (*ecosystems.PluginResult, error) {
	return f.result, f.err
}

func newResolveDepgraphsCtx(t *testing.T) (*gafmocks.MockInvocationContext, *gafmocks.MockEngine) {
	t.Helper()

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	engine := gafmocks.NewMockEngine(ctrl)
	cfg := configuration.New()
	logger := zerolog.Nop()

	ictx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	ictx.EXPECT().Context().Return(context.Background()).AnyTimes()

	return ictx, engine
}

func TestResolveDepgraphs_FailFastReturnsCreateFailFastError(t *testing.T) {
	ictx, _ := newResolveDepgraphsCtx(t)

	plugin := fakePlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{{
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{TargetFile: ptr("requirements.txt")},
				},
				Error: errors.New("plugin boom"),
			}},
		},
	}

	opts := *ecosystems.NewPluginOptions().WithAllProjects(true).WithFailFast(true)

	resultsChan, err := resolveDepgraphsDI(ictx, ".", opts, []ecosystems.SCAPlugin{plugin})

	require.Error(t, err)
	assert.Nil(t, resultsChan)
	assert.Contains(t, err.Error(), "requirements.txt")

	// The //nolint:wrapcheck above HandleFailFastResult exists so os-flows can
	// detect the exit code and render its ErrorCatalog. Pin that contract.
	var ec ecosystems.ExitCoder
	require.ErrorAs(t, err, &ec)
	assert.Equal(t, 2, ec.ExitCode(), "fail-fast errors must surface exit code 2 to os-flows")
}

func TestResolveDepgraphs_SkipsLegacyWhenResultsAndNotAllProjects(t *testing.T) {
	ictx, engine := newResolveDepgraphsCtx(t)

	// Make the "must not be called" assertion explicit so it survives any future
	// loosening of gomock's strict-by-default controller.
	engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Times(0)

	plugin := fakePlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{{
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{TargetFile: ptr("requirements.txt")},
				},
			}},
			ProcessedFiles: []string{"requirements.txt"},
		},
	}

	opts := *ecosystems.NewPluginOptions()

	resultsChan, err := resolveDepgraphsDI(ictx, ".", opts, []ecosystems.SCAPlugin{plugin})

	require.NoError(t, err)
	require.NotNil(t, resultsChan)

	//nolint:prealloc // preallocation adds no value.
	var collected []ecosystems.SCAResult
	for r := range resultsChan {
		collected = append(collected, r)
	}
	require.Len(t, collected, 1)
	assert.Equal(t, "requirements.txt", collected[0].ProjectDescriptor.GetTargetFile())
}

func TestResolveDepgraphs_RunsAllPluginsWhenAllProjects(t *testing.T) {
	ictx, engine := newResolveDepgraphsCtx(t)

	engine.EXPECT().
		InvokeWithConfig(gomock.Any(), gomock.Any()).
		Return([]workflow.Data{
			workflow.NewData(
				workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier(internalworkflow.LegacyCLIWorkflowIDStr), "application/text"),
				"application/text",
				[]byte(`{"depGraph":{"pkgManager":{"name":"npm"}},"normalisedTargetFile":"package.json","target":{}}`),
			),
		}, nil).
		Times(1)

	plugin := fakePlugin{
		result: &ecosystems.PluginResult{
			Results: []ecosystems.SCAResult{{
				ProjectDescriptor: identity.ProjectDescriptor{
					Identity: identity.ProjectIdentity{TargetFile: ptr("requirements.txt")},
				},
			}},
		},
	}

	opts := *ecosystems.NewPluginOptions().WithAllProjects(true)

	resultsChan, err := resolveDepgraphsDI(ictx, ".", opts, []ecosystems.SCAPlugin{plugin, legacy.NewPlugin(ictx)})

	require.NoError(t, err)
	require.NotNil(t, resultsChan)

	//nolint:prealloc // preallocation adds no value.
	var collected []ecosystems.SCAResult
	for r := range resultsChan {
		collected = append(collected, r)
	}
	// 1 plugin result + 1 legacy result.
	require.Len(t, collected, 2)
}

func TestResolveDepgraphs_WrapsPluginError(t *testing.T) {
	ictx, _ := newResolveDepgraphsCtx(t)

	plugin := fakePlugin{err: errors.New("plugin exploded")}

	opts := *ecosystems.NewPluginOptions().WithAllProjects(true)

	resultsChan, err := resolveDepgraphsDI(ictx, ".", opts, []ecosystems.SCAPlugin{plugin})

	require.Error(t, err)
	assert.Nil(t, resultsChan)
	assert.Contains(t, err.Error(), "plugin exploded")
}
