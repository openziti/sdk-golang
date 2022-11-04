package ziti

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
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

func ForAllContexts(f func(ctx Context) bool) {
	contexts.Range(func(key, value any) bool {
		ziti := value.(Context)
		return f(ziti)
	})
}
