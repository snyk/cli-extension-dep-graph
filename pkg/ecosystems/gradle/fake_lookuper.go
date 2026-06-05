//go:build !release

package gradle

// This file contains test utilities and is excluded from release builds.

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/snyk/cli-extension-dep-graph/v2/internal/snykclient"
)

// fakeLookuper is a programmable packageLookuper used to drive the normalize-deps
// post-hook without making real HTTP calls. It records the sequence of SHA1s queried so
// tests can verify dedup behavior.
//
//nolint:unused // only used in tests
type fakeLookuper struct {
	mu         sync.Mutex
	calls      map[string]int
	responses  map[string]string // sha1 -> canonical purl ("" = no mapping)
	errors     map[string]error  // sha1 -> error to return
	totalCalls atomic.Int64
}

//nolint:unused // only used in tests
func newFakeLookuper() *fakeLookuper {
	return &fakeLookuper{
		calls:     make(map[string]int),
		responses: make(map[string]string),
		errors:    make(map[string]error),
	}
}

//nolint:unused // only used in tests
func (f *fakeLookuper) LookupMavenPackage(_ context.Context, q snykclient.MavenPackageQuery) (string, error) {
	f.totalCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[q.SHA1]++
	if err, ok := f.errors[q.SHA1]; ok {
		return "", err
	}
	return f.responses[q.SHA1], nil
}

//nolint:unused // only used in tests
func (f *fakeLookuper) callCount(sha1 string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[sha1]
}
