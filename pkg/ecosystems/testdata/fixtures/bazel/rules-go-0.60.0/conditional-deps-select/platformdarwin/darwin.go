package platformdarwin

// Name is only ever compiled into the binary on darwin, because the go_library
// that depends on it is selected only under the ":darwin" config_setting.
func Name() string {
	return "darwin"
}
