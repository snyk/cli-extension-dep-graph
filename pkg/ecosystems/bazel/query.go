package bazel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// TODO: support custom bazel command? like bazelisk or custom path to bazel binary.
const bazelCommand = "bazel"

// bazelTarget is the shape of a single target entry as emitted by both
// `cquery --output=jsonproto` (nested under queryResults.Results) and
// `query --output=streamed_jsonproto` (one per line).
type bazelTarget struct {
	Type string `json:"type"`
	Rule *struct {
		Name      string `json:"name"`
		Attribute []struct {
			Name            string   `json:"name"`
			StringListValue []string `json:"stringListValue"`
		} `json:"attribute"`
	} `json:"rule"`
}

type queryResults struct {
	Results []struct {
		Target *bazelTarget `json:"target"`
	} `json:"results"`
}

// wrapBazelErr formats a bazel command failure, including stderr when known.
func wrapBazelErr(args []string, err error, stderr string) error {
	if stderr != "" {
		return fmt.Errorf("bazel %s: %w: %s", strings.Join(args, " "), err, stderr)
	}
	return fmt.Errorf("bazel %s: %w", strings.Join(args, " "), err)
}

// bazelCquery runs the analysis phase (`bazel cquery`), which resolves any
// select() in the query's transitive closure against a concrete
// configuration. Use this where over-reporting select() branches would be
// wrong (e.g. computing a target's actual deps). If platform is non-empty, it
// is passed as --platforms so the caller can pick the resolved configuration
// instead of relying on the host's auto-detected platform.
func bazelCquery(ctx context.Context, dir, query, platform string) (*queryResults, error) {
	args := []string{"cquery", query, "--output=jsonproto"}
	if platform != "" {
		args = append(args, "--platforms="+platform)
	}

	cmd := exec.CommandContext(ctx, bazelCommand, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, wrapBazelErr(args, err, string(exitErr.Stderr))
		}
		return nil, wrapBazelErr(args, err, "")
	}

	var results queryResults
	if err := json.Unmarshal(out, &results); err != nil {
		return nil, fmt.Errorf("parse bazel cquery json: %w", err)
	}
	return &results, nil
}

// bazelStreamedQuery runs the loading phase only (`bazel query`), which never
// resolves select() and so cannot fail on a configuration mismatch. Use this
// for target discovery: a select() lives in attributes like deps, never in
// whether a rule exists, so query and cquery return identical target sets for
// discovery queries.
//
// --output=streamed_jsonproto emits one target per line, so results are
// decoded directly off the process's stdout pipe as bazel writes them,
// rather than buffering the whole (potentially very large, monorepo-wide)
// output in memory before parsing.
func bazelStreamedQuery(ctx context.Context, dir, query string) ([]*bazelTarget, error) {
	args := []string{"query", query, "--output=streamed_jsonproto"}
	cmd := exec.CommandContext(ctx, bazelCommand, args...)
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, wrapBazelErr(args, err, "")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, wrapBazelErr(args, err, "")
	}

	var targets []*bazelTarget
	dec := json.NewDecoder(stdout)
	for {
		var t bazelTarget
		if err := dec.Decode(&t); err != nil {
			if err == io.EOF {
				break
			}
			// The decode error is usually just a symptom of the process
			// having failed; prefer that as the more informative error.
			if waitErr := cmd.Wait(); waitErr != nil {
				return nil, wrapBazelErr(args, waitErr, stderr.String())
			}
			return nil, fmt.Errorf("parse bazel query streamed_jsonproto: %w", err)
		}
		targets = append(targets, &t)
	}

	if err := cmd.Wait(); err != nil {
		return nil, wrapBazelErr(args, err, stderr.String())
	}
	return targets, nil
}
