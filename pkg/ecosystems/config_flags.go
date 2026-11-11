package ecosystems

import "github.com/snyk/go-application-framework/pkg/configuration"

type configFlag struct {
	keys    []string
	present func(configuration.Configuration, string) bool
	apply   func(configuration.Configuration, string) error
}

func applyConfigFlags(config configuration.Configuration, flags ...configFlag) error {
	for _, flag := range flags {
		for _, key := range flag.keys {
			present := config.IsSet(key)
			if flag.present != nil {
				present = flag.present(config, key)
			}
			if !present {
				continue
			}
			if err := flag.apply(config, key); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

func boolFlag(key string, target *bool) configFlag {
	return configFlag{
		keys: []string{key},
		apply: func(config configuration.Configuration, key string) error {
			*target = config.GetBool(key)
			return nil
		},
	}
}

func stringFlag(key string, target *string, aliases ...string) configFlag {
	return configFlag{
		keys: append([]string{key}, aliases...),
		apply: func(config configuration.Configuration, key string) error {
			*target = config.GetString(key)
			return nil
		},
	}
}

func parsedStringFlag[T any](key string, target *T, parse func(string) (T, error)) configFlag {
	return configFlag{
		keys: []string{key},
		apply: func(config configuration.Configuration, key string) error {
			value, err := parse(config.GetString(key))
			if err != nil {
				return err
			}
			*target = value
			return nil
		},
	}
}

func nonEmptyStringFlag(key string, target **string) configFlag {
	return configFlag{
		keys: []string{key},
		// --file accepts a nonempty framework default as well as explicit config.
		present: func(config configuration.Configuration, key string) bool {
			return config.GetString(key) != ""
		},
		apply: func(config configuration.Configuration, key string) error {
			value := config.GetString(key)
			*target = &value
			return nil
		},
	}
}
