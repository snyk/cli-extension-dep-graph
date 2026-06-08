package yarn

import (
	"context"
	"fmt"
	"io"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// parseYarnInfoOutput parses Berry `yarn info --all --recursive --json` output.
// Berry emits NDJSON: one JSON object per line, each describing a resolved
// package and its direct dependencies. The root workspace appears as a value
// ending in "@workspace:."; workspace members end in "@workspace:<path>".
//
// Locators carry protocol prefixes (npm:, workspace:, file:, patch:, …) and
// peer-virtual entries appear as `name@virtual:<hash>#<realProtocol>:<version>`.
// We de-virtualise locators by stripping the `@virtual:.*#` infix so virtuals
// collapse to their underlying real package id; protocol prefixes are kept on
// graph keys and stripped only at PkgInfo extraction time by splitPkgID.
//
// Not implemented yet — populated in the Berry-path commit.
func parseYarnInfoOutput(
	_ context.Context,
	_ logger.Logger,
	_ io.Reader,
	_ *packageJSON,
) (*parsedOutput, error) {
	return nil, fmt.Errorf("yarn berry parser not yet implemented")
}
