// Package main is workspace member svc-b — a stdlib-only program so
// the workspace fixture stays offline-safe with no external deps.
package main

import "fmt"

func main() {
	fmt.Println("svc-b")
}
