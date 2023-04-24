// Package ziti provides methods for loading ziti contexts from identity JSON files
// Identity files specifies in `ZITI_IDENTITIES` environment variable (semicolon separates) are loaded automatically
// at startup
package ziti

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge-api/rest_model"
	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/posture"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pkg/errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var contexts = new(sync.Map)

func init() {
	ids := os.Getenv("ZITI_IDENTITIES")

	idlist := strings.Split(ids, ";")

	for _, id := range idlist {

		if id == "" {
			continue
		}

		_, err := LoadContext(id)
		if err != nil {
			pfxlog.Logger().Errorf("failed to load config from '%s'", id)
			continue
		}
	}
}

// LoadContext loads a configuration from the supplied path. The configuration specifies
// location of the controller's Edge Client API, the configuration types to request for
// services, and the identity configuration that specifies where the client certificate
// and private key are loaded from. See the [identity repository](https://githb.com/openziti/identity
// for more details.
//
// Creating a Context using this function requires an identity configuration and only
// supports certificate based authentication. For other authentication flows
// see NewContext().
//
// ```
//
//	{
//	  "ztAPI": "https://ziti.controller.example.com/edge/client/v1",
//	  "configTypes": ["config1", "config2"],
//	  "id": { "cert": "...", "key": "..." },
//	}
//
// ```
func LoadContext(configPath string) (Context, error) {
	var cfg *Config

	path, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	cfg, err = NewConfigFromFile(path)
	if err != nil {
		return nil, err
	}

	cfg.ConfigTypes = append(cfg.ConfigTypes, InterceptV1, ClientConfigV1)
	newCtx, err := NewContext(cfg)

	if err != nil {
		return nil, err
	}

	ctx, exists := contexts.LoadOrStore(path, newCtx)

	ztx := ctx.(*ContextImpl)
	if exists {
		newCtx.Close()
	} else {
		err = ztx.Authenticate()
		if err != nil {
			contexts.Delete(path)
			ztx.Close()
			return nil, err
		}
	}

	return ztx, nil
}

// ForAllContexts iterates over all Ziti contexts loaded from ZITI_IDENTITIES environment variable,
// or with LoadContext() call
func ForAllContexts(f func(ctx Context) bool) {
	contexts.Range(func(key, value any) bool {
		ziti := value.(Context)
		return f(ziti)
	})
}

// NewContext creates a Context from the supplied Config with the default options. See NewContextWithOpts().
func NewContext(cfg *Config) (Context, error) {
	return NewContextWithOpts(cfg, nil)
}

// NewContextWithOpts creates a Context from the supplied Config and Options. The configuration requires
// either the `ID` field or the  `Credentials` field to be populated. If both are supplied the, the ID field is used.
func NewContextWithOpts(cfg *Config, options *Options) (Context, error) {
	if options == nil {
		options = DefaultOptions
	}

	newContext := &ContextImpl{
		routerConnections: cmap.New[edge.RouterConn](),
		options:           options,
		authQueryHandlers: map[string]func(query *rest_model.AuthQueryDetail, resp func(code string) error) error{},
		closeNotify:       make(chan struct{}),
	}

	if cfg == nil {
		return nil, errors.New("a config is required")
	}

	if cfg.ID.Cert != "" && cfg.ID.Key != "" {
		cfg.Credentials = edge_apis.NewIdentityCredentialsFromConfig(cfg.ID)
	} else if cfg.Credentials == nil {
		return nil, errors.New("either cfg.ID or cfg.Credentials must be provided")
	}

	apiUrl, err := url.Parse(cfg.ZtAPI)

	if err != nil {
		return nil, errors.Wrap(err, "could not parse ZtAPI from configuration as URI")
	}

	newContext.CtrlClt = &CtrlClient{
		ClientApiClient: edge_apis.NewClientApiClient(apiUrl, cfg.Credentials.GetCaPool()),
		Credentials:     cfg.Credentials,
	}

	newContext.CtrlClt.PostureCache = posture.NewCache(newContext.CtrlClt, newContext.closeNotify)

	return newContext, nil
}
