// Package childenv builds environments for child processes that must not inherit Snyk settings.
package childenv

import (
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/subprocess"
)

const snykPrefix = "snyk_"

// Environ returns the current environment without SNYK_ variables, for use in cmd.Env of a child process run in dir.
func Environ(dir string) ([]string, error) {
	env, err := subprocess.SanitizeEnv(os.Environ(), dir, snykPrefix)
	if err != nil {
		return nil, fmt.Errorf("sanitize environment: %w", err)
	}
	return env, nil
}
