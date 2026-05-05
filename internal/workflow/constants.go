package workflow

const (
	ContentTypeJSON        = "application/json"
	ContentTypeJSONL       = "application/jsonl"
	LegacyCLIWorkflowIDStr = "legacycli"
	ContentLocationKey     = "Content-Location"

	FeatureFlagUvCLI                         = "internal_snyk_cli_uv_enabled"
	FeatureFlagUseUnifiedTestAPIForOSCliTest = "internal_snyk_cli_use_unified_test_api_for_os_cli_test"
)

var (
	MetaKeyNormalisedTargetFile = "normalisedTargetFile"
	MetaKeyTargetFileFromPlugin = "targetFileFromPlugin"
	MetaKeyTarget               = "target"
)
