package yarn

import (
	"context"
	"fmt"
	"io"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/logger"
)

// parseYarnListOutput parses Yarn Classic `yarn list --depth=Infinity --json`
// output: a single JSON line of the shape
//
//	{"type":"tree","data":{"type":"list","trees":[{"name":"<pkg@version>","children":[{"name":"<dep@spec>"}]}]}}
//
// Each tree node's name is a resolved "name@version"; each child's name is the
// declared specifier ("name@~1.2.3", "name@^4") which may not match the
// resolved version exactly. We disambiguate by matching the specifier against
// resolved sibling versions via semver (see the v1-path commit).
//
// Workspace packages are NOT distinguished in `yarn list` output; the parser
// reads the root package.json's `workspaces` field and resolves each
// workspace's package.json under lockFileDir to populate parsedOutput.Workspaces.
//
// Not implemented yet — populated in the v1-path commit.
func parseYarnListOutput(
	_ context.Context,
	_ logger.Logger,
	_ io.Reader,
	_ *packageJSON,
	_ string,
) (*parsedOutput, error) {
	return nil, fmt.Errorf("yarn classic parser not yet implemented")
}
