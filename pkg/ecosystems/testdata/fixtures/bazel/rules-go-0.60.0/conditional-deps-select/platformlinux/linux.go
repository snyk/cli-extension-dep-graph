package platformlinux

// Name is only ever compiled into the binary on linux, because the go_library
// that depends on it is selected only under the ":linux" config_setting.
func Name() string {
	return "linux"
}
