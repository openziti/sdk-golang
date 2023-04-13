// Package ziti provides methods for loading ziti contexts from identity JSON files
// Identity files specifies in `ZITI_IDENTITIES` environment variable (semicolon separates) are loaded automatically
// at startup
package ziti

import (
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge-api/rest_client_api_client"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/ziti/config"
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

// LoadContext returns Ziti context for the given identity file loading it if needed
func LoadContext(config_ string) (Context, error) {
	var cfg *config.Config

	path, err := filepath.Abs(config_)
	if err != nil {
		return nil, err
	}
	cfg, err = config.NewFromFile(path)
	if err != nil {
		return nil, err
	}

	cfg.ConfigTypes = append(cfg.ConfigTypes, InterceptV1, ClientConfigV1)
	newCtx, err := NewContextWithConfig(cfg)

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

func NewContext() (Context, error) {
	return NewContextWithConfig(nil)
}

func NewContextWithConfig(cfg *config.Config) (Context, error) {
	return NewContextWithOpts(cfg, nil)
}

func NewContextWithOpts(cfg *config.Config, options *Options) (Context, error) {
	if options == nil {
		options = DefaultOptions
	}

	newContext := &ContextImpl{
		routerConnections: cmap.New[edge.RouterConn](),
		options:           options,
		authQueryHandlers: map[string]func(query *rest_model.AuthQueryDetail, resp func(code string) error) error{},
		closeNotify:       make(chan struct{}),
	}

	ztUrl, err := url.Parse(cfg.ZtAPI)

	if err != nil {
		return nil, err
	}

	newContext.CtrlClt = &CtrlClient{
		CaPool: cfg.CaPool,
	}

	ctrlUrl, err := url.Parse(cfg.ZtAPI)

	if err != nil {
		return nil, errors.Wrap(err, "could not parse ZtAPI from configuration as URI")
	}

	if cfg.Authenticator == nil {
		return nil, errors.New("authenticator must not be nil")
	}

	httpClient, err := cfg.Authenticator.BuildHttpClient()

	if err != nil {
		return nil, errors.Wrap(err, "could not build HTTP client")
	}

	clientRuntime := httptransport.NewWithClient(ctrlUrl.Host, rest_client_api_client.DefaultBasePath, rest_client_api_client.DefaultSchemes, httpClient)
	clientRuntime.DefaultAuthentication = newContext.CtrlClt

	newContext.CtrlClt.ZitiEdgeClient = rest_client_api_client.New(clientRuntime, nil)
	newContext.CtrlClt.Authenticator = cfg.Authenticator
	newContext.CtrlClt.EdgeClientApiUrl = ztUrl

	if err != nil {
		return nil, err
	}

	newContext.CtrlClt.PostureCache = posture.NewCache(newContext.CtrlClt, newContext.closeNotify)

	return newContext, nil
}
