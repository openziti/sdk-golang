package ziti

import "path/filepath"

// Deprecated: DefaultCollection is deprecated and is included for legacy support.
// It powers two other deprecated functions: `ForAllContext() and and `LoadContext()` which rely on it. The intended
// replacement is for implementations that wish to have this functionality to use NewSdkCollection() or
// NewSdkCollectionFromEnv() on their own.
var DefaultCollection *SdkCollection

func init() {
	DefaultCollection = NewSdkCollectionFromEnv("ZITI_IDENTITIES")
}

// Deprecated: ForAllContexts iterates over all Context instances in the DefaultCollection and call the provided function `f`.
// Usage of the DefaultCollection is advised against, and if this functionality is needed, implementations should
// instantiate their own SdkCollection via NewSdkCollection() or NewSdkCollectionFromEnv()
func ForAllContexts(f func(ctx Context) bool) {
	DefaultCollection.ForAll(f)
}

// Deprecated: LoadContext loads a configuration from the supplied path into the DefaultCollection as a convenience.
// Usage of the DefaultCollection is advised against, and if this functionality is needed, implementations should
// instantiate their own SdkCollection via NewSdkCollection() or NewSdkCollectionFromEnv()
//
// LoadContext will attempt to load a Config from the provided path. See NewConfigFromFile() for details.
// ```
func LoadContext(configPath string) (Context, error) {
	path, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}

	cfg, err := NewConfigFromFile(path)

	if err != nil {
		return nil, err
	}

	cfg.ConfigTypes = append(cfg.ConfigTypes, InterceptV1, ClientConfigV1)

	ctx, err := DefaultCollection.NewContext(cfg)

	if err != nil {
		return nil, err
	}

	err = ctx.Authenticate()

	if err != nil {
		DefaultCollection.Remove(ctx)
		ctx.Close()
	}

	return ctx, nil
}
