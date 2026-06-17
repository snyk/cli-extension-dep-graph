package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems"
)

// fakeResolver mimics PluginRegistry.ResolveDepgraphs: it emits results on an
// unbuffered channel from a goroutine whose sends are guarded by ctx.Done(), so
// canceling the context is what unblocks a parked send. It records the context
// the adapter handed it, letting tests assert cancellation propagated.
type fakeResolver struct {
	results []ecosystems.SCAResult
	//nolint:containedctx // intentional: captures the context the adapter passes via the registry, to assert cancellation.
	ctx  context.Context
	done chan struct{}
}

func (f *fakeResolver) ResolveDepgraphs(_ string, _ *ecosystems.SCAPluginOptions) <-chan ecosystems.SCAResult {
	ch := make(chan ecosystems.SCAResult)
	go func() {
		defer close(ch)
		defer close(f.done)
		for _, r := range f.results {
			select {
			case ch <- r:
			case <-f.ctx.Done():
				return
			}
		}
	}()
	return ch
}

func newTestPlugin(t *testing.T, resolver depgraphResolver, registryErr error) *Plugin {
	t.Helper()
	return &Plugin{
		ictx: setupMockInvocationContext(t),
		newRegistry: func(ictx workflow.InvocationContext) (depgraphResolver, error) {
			if registryErr != nil {
				return nil, registryErr
			}
			if fr, ok := resolver.(*fakeResolver); ok {
				fr.ctx = ictx.Context()
			}
			return resolver, nil
		},
	}
}

func result(targetFile string) ecosystems.SCAResult {
	return ecosystems.SCAResult{
		ResolverMetadata: &ecosystems.ResolverMetadata{NormalisedTargetFile: targetFile},
	}
}

func TestPlugin_GetName(t *testing.T) {
	assert.Equal(t, "orchestrator", NewPlugin(nil).GetName())
}

func TestPlugin_BuildDepGraphsFromDir_ForwardsAllResults(t *testing.T) {
	fake := &fakeResolver{
		results: []ecosystems.SCAResult{result("a"), result("b"), result("c")},
		done:    make(chan struct{}),
	}
	p := newTestPlugin(t, fake, nil)

	var got []string
	err := p.BuildDepGraphsFromDir(context.Background(), nil, "/dir", ecosystems.NewPluginOptions(), func(r ecosystems.SCAResult) error {
		got = append(got, r.ResolverMetadata.NormalisedTargetFile)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, got)
}

// TestPlugin_BuildDepGraphsFromDir_AbortCancelsResolver proves the SCAPlugin
// contract: a non-nil onGraph return aborts the run AND the resolver's context is
// canceled so its goroutine unwinds (no leak), without a manual drain loop.
func TestPlugin_BuildDepGraphsFromDir_AbortCancelsResolver(t *testing.T) {
	fake := &fakeResolver{
		results: []ecosystems.SCAResult{result("a"), result("b"), result("c")},
		done:    make(chan struct{}),
	}
	p := newTestPlugin(t, fake, nil)

	abortErr := errors.New("stop now")
	calls := 0
	err := p.BuildDepGraphsFromDir(context.Background(), nil, "/dir", ecosystems.NewPluginOptions(), func(_ ecosystems.SCAResult) error {
		calls++
		return abortErr
	})

	require.ErrorIs(t, err, abortErr)
	assert.Equal(t, 1, calls, "onGraph should not be called again after it aborts")

	select {
	case <-fake.done:
		// resolver goroutine unwound via ctx cancellation — no leak.
	case <-time.After(2 * time.Second):
		t.Fatal("resolver goroutine leaked: not canceled after onGraph aborted")
	}
}

func TestPlugin_BuildDepGraphsFromDir_RegistryError(t *testing.T) {
	p := newTestPlugin(t, nil, errors.New("boom"))

	err := p.BuildDepGraphsFromDir(context.Background(), nil, "/dir", ecosystems.NewPluginOptions(), func(ecosystems.SCAResult) error {
		t.Fatal("onGraph must not be called when registry construction fails")
		return nil
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create plugin registry")
	assert.Contains(t, err.Error(), "boom")
}

func TestPlugin_BuildDepGraphsFromDir_NilOptions(t *testing.T) {
	p := newTestPlugin(t, &fakeResolver{done: make(chan struct{})}, nil)

	err := p.BuildDepGraphsFromDir(context.Background(), nil, "/dir", nil, func(ecosystems.SCAResult) error {
		return nil
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "without options")
}

// TestPlugin_buildOrchestratorOptions_CarriesBatchFields locks in that the batch
// fields the SBOM flow relies on (ExcludePaths from earlier plugins, AllProjects)
// survive onto the os-flows-style options built from raw flags.
func TestPlugin_buildOrchestratorOptions_CarriesBatchFields(t *testing.T) {
	p := &Plugin{ictx: setupMockInvocationContext(t)}

	in := ecosystems.NewPluginOptions()
	in.Global.AllProjects = true
	in.Global.ExcludePaths = ecosystems.CommaSeparatedString{"uv/uv.lock", "uv/sub/uv.lock"}

	out, err := p.buildOrchestratorOptions(in)

	require.NoError(t, err)
	assert.True(t, out.Global.AllProjects)
	assert.Equal(t, ecosystems.CommaSeparatedString{"uv/uv.lock", "uv/sub/uv.lock"}, out.Global.ExcludePaths)
}
