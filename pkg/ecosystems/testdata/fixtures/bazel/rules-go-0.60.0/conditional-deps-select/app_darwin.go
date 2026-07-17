//go:build darwin

package main

import "conditional-deps-select/platformdarwin"

func platformName() string {
	return platformdarwin.Name()
}
