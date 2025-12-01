package pip

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// FixtureExecutor reads pip reports from pip_report.json fixture files.
type FixtureExecutor struct{}

func (f *FixtureExecutor) Execute(ctx context.Context, _ string, args ...string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, &pipError{err: ctx.Err(), stderr: ""}
	}

	var reqFile string
	for i, arg := range args {
		if arg == "-r" && i+1 < len(args) {
			reqFile = args[i+1]
			break
		}
	}

	if reqFile == "" {
		return nil, &pipError{
			err:    context.Canceled,
			stderr: "no requirements file specified",
		}
	}

	fixtureFile := filepath.Join(filepath.Dir(reqFile), "pip_report.json")
	data, err := os.ReadFile(fixtureFile)
	if err != nil {
		return nil, &pipError{
			err:    err,
			stderr: fmt.Sprintf("pip_report.json not found at %s", fixtureFile),
		}
	}

	return data, nil
}

// MockErrorExecutor simulates pip errors for testing error classification.
type MockErrorExecutor struct {
	Stderr string
}

func (m *MockErrorExecutor) Execute(ctx context.Context, _ string, _ ...string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, &pipError{err: ctx.Err(), stderr: ""}
	}

	return nil, &pipError{
		err:    fmt.Errorf("exit status 1"),
		stderr: m.Stderr,
	}
}
