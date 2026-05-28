// Go uses this file to track module dependencies and to mark the root directory
// of a Go module. This file is maintained with Go tools outside of Bazel.
// For example, you can use 'bazel run @rules_go//go -- mod tidy' or
// 'go mod tidy' to add requirements for missing modules.
//
// Gazelle's go_deps module extension imports dependency declarations
// from this file.

module github.com/bazel-contrib/rules_go/examples/basic_gazelle

go 1.23.4

require (
	github.com/stretchr/testify v1.10.0
	golang.org/x/net v0.38.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Versioned replace (bzlmod): dep-graph must use v0.39.0 while the Bazel repo key stays org_golang_x_net.
replace golang.org/x/net => golang.org/x/net v0.39.0
