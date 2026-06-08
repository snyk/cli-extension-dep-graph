// Package main is the simple acceptance fixture: a single module
// importing one external dep so the integration test can verify the
// resolver end-to-end against `go list`.
package main

import (
	"fmt"

	"golang.org/x/mod/semver"
)

func main() {
	fmt.Println(semver.IsValid("v1.0.0"))
}
