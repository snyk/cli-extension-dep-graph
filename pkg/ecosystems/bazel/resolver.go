package bazel

import (
	"context"
	"errors"
	"fmt"

	"github.com/snyk/dep-graph/go/pkg/depgraph"

	"github.com/snyk/cli-extension-dep-graph/pkg/ecosystems"
)

type bazelDependencyResolver interface {
	packageManagerName() string
	findTargets(ctx context.Context, options *ecosystems.SCAPluginOptions) ([]string, error)
	buildDepGraph(ctx context.Context, targetName string) (*depgraph.DepGraph, error)
	processedFiles() []string
}

const (
	errQueryBazelTargetsFmt = "failed to query bazel targets: %w"
	errBazelResolverFmt     = "bazel resolver: %w"
)

var (
	errNoBazelOptionFound    = errors.New("no bazel option found")
	errBazelOptionsExclusive = errors.New("--bazel-jvm and --bazel-go are mutually exclusive")
)

func newResolverFromOptions(
	dir string,
	options *ecosystems.SCAPluginOptions,
) (bazelDependencyResolver, error) {
	if options == nil {
		return nil, fmt.Errorf(errBazelResolverFmt, errNoBazelOptionFound)
	}

	switch {
	case options.Bazel.Jvm && options.Bazel.Go:
		return nil, fmt.Errorf(errBazelResolverFmt, errBazelOptionsExclusive)
	case options.Bazel.Jvm:
		r, err := newJVMExternalResolver(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to create bazel jvm external resolver: %w", err)
		}
		return r, nil
	case options.Bazel.Go:
		r, err := newGoResolver(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to create bazel go resolver: %w", err)
		}
		return r, nil
	default:
		return nil, fmt.Errorf(errBazelResolverFmt, errNoBazelOptionFound)
	}
}
