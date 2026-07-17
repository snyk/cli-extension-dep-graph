package main

// main is platform-independent; the platform-specific dependency is pulled in
// via platformName(), which is defined in a build-constrained file
// (app_linux.go or app_darwin.go). This mirrors how gazelle emits a select()
// on `deps` for sources guarded by //go:build constraints.
func main() {
	println(platformName())
}
