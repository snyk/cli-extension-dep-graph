package discovery

var commonExcludes = []string{
	// Any hidden folder
	".*",

	// Common build directories
	"dist",
	"build",

	// JavaScript/Node.js
	"node_modules",
	".next",
	".nuxt",

	// Python (pip, poetry, uv)
	"__pycache__",
	"*.egg-info",
	"*.dist-info",
	"venv",
	"env",

	// Go
	"vendor",

	// Ruby (Bundler)
	".bundle",

	// Swift/iOS
	"Pods",
	"Carthage",
}
