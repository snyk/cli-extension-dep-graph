//go:build linux

package main

import "conditional-deps-select/platformlinux"

func platformName() string {
	return platformlinux.Name()
}
