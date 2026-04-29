module github.com/bazelbuild/rules_go/examples/basic-gazelle

go 1.19

require (
	github.com/spf13/cobra v1.5.0
	k8s.io/klog/v2 v2.80.1
)

require (
	github.com/go-logr/logr v1.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)

// Versioned replace: dep-graph must use v1.6.1 while the Bazel repo key stays com_github_spf13_cobra.
replace github.com/spf13/cobra => github.com/spf13/cobra v1.6.1
