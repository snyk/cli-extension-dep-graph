package bazel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
)

// TODO: support custom bazel command? like bazelisk or custom path to bazel binary.
const bazelCommand = "bazel"

type queryResults struct {
	Results []struct {
		Target *struct {
			Type string `json:"type"`
			Rule *struct {
				Name      string `json:"name"`
				Attribute []struct {
					Name            string   `json:"name"`
					StringListValue []string `json:"stringListValue"`
				} `json:"attribute"`
			} `json:"rule"`
		} `json:"target"`
	} `json:"results"`
}

func bazelQuery(ctx context.Context, dir, query string) (*queryResults, error) {
	cmd := exec.CommandContext(ctx, bazelCommand, "cquery", query, "--output=jsonproto")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("bazel query %q: %w: %s", query, err, string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("bazel query %q: %w", query, err)
	}

	var results queryResults
	if err := json.Unmarshal(out, &results); err != nil {
		return nil, fmt.Errorf("parse bazel query json: %w", err)
	}
	return &results, nil
}
