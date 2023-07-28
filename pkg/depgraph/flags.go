package depgraph

import "github.com/spf13/pflag"

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("depgraph", pflag.ExitOnError)

	flagSet.Bool("fail-fast", false, "Fail fast when scanning all projects")
	flagSet.Bool("all-projects", false, "Enable all projects")
	flagSet.Bool("dev", false, "Include dev dependencies")
	flagSet.String("file", "", "Input file")
	flagSet.String("detection-depth", "", "Detection depth")
	flagSet.BoolP("prune-repeated-subdependencies", "p", false, "Prune repeated sub-dependencies")

	return flagSet
}
