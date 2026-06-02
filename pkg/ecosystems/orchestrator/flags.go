package orchestrator

type flag struct {
	Key   string
	Value string
}

var FlagUnifiedTestAPIOsCLI = flag{
	Key:   "internal_snyk_cli_use_unified_test_api_for_os_cli_test",
	Value: "unified-test-api-os-cli",
}

var FlagNewGradleResolver = flag{
	Key:   "internal_new_gradle_resolver",
	Value: "internal-new-gradle-resolver",
}

var FlagBazelResolver = flag{
	Key:   "internal-bazel-resolver",
	Value: "internal-bazel-resolver",
}

var FlagBunResolver = flag{
	Key:   "internal-bun-resolver",
	Value: "internal-bun-resolver",
}

var FlagCargoResolver = flag{
	Key:   "internal-cargo-resolver",
	Value: "internal-cargo-resolver",
}

var allFlags = []flag{
	FlagUnifiedTestAPIOsCLI,
	FlagNewGradleResolver,
	FlagBazelResolver,
	FlagBunResolver,
	FlagCargoResolver,
}

// GetAllFlags returns all feature flags as a map of key to flag name.
func GetAllFlags() map[string]string {
	result := make(map[string]string, len(allFlags))
	for _, f := range allFlags {
		result[f.Key] = f.Value
	}
	return result
}
