// Package main provides a test helper binary for testing command execution.
// This helper allows tests to control what is written to stdout and stderr,
// and what exit code is returned, enabling verification of how the executor
// handles different output scenarios.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			versionEnv := os.Getenv("TESTHELPER_VERSION")
			fmt.Fprintf(os.Stdout, "testhelper %s\n", versionEnv)
			os.Exit(0)
		}
	}

	stdout := flag.String("stdout", "", "content to write to stdout")
	stderr := flag.String("stderr", "", "content to write to stderr")
	exitCode := flag.Int("exit", 0, "exit code to return")
	flag.Parse()

	if *stdout != "" {
		fmt.Fprint(os.Stdout, *stdout)
	}
	if *stderr != "" {
		fmt.Fprint(os.Stderr, *stderr)
	}
	os.Exit(*exitCode)
}
