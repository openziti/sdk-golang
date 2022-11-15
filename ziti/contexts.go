// Package ziti provides methods for loading ziti contexts from identity JSON files
// Identity files specifies in `ZITI_IDENTITIES` environment variable (semicolon separates) are loaded automatically
// at startup
package ziti

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/api"
	"github.com/openziti/sdk-golang/ziti/edge/posture"
	cmap "github.com/orcaman/concurrent-map/v2"
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

	cfg.ConfigTypes = append(cfg.ConfigTypes, edge.InterceptV1, edge.ClientConfigV1)
	newCtx := NewContextWithConfig(cfg).(*contextImpl)
	ctx, exists := contexts.LoadOrStore(path, newCtx)

	ztx := ctx.(*contextImpl)
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

func NewContext() Context {
	return NewContextWithConfig(nil)
}

func NewContextWithConfig(cfg *config.Config) Context {
	return NewContextWithOpts(cfg, nil)
}

func NewContextWithOpts(cfg *config.Config, options *Options) Context {
	if options == nil {
		options = DefaultOptions
	}

	result := &contextImpl{
		routerConnections: cmap.New[edge.RouterConn](),
		options:           options,
		authQueryHandlers: map[string]func(query *edge.AuthQuery, resp func(code string) error) error{},
		closeNotify:       make(chan struct{}),
	}

	result.ctrlClt = api.NewLazyClient(cfg, func(ctrlClient api.Client) error {
		result.postureCache = posture.NewCache(ctrlClient, result.closeNotify)
		return nil
	})

	return result
}
