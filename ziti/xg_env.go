package ziti

import (
	"github.com/openziti/metrics"
	"github.com/openziti/sdk-golang/xgress"
)

type xgEnv struct {
	payloadIngester *xgress.PayloadIngester
	metrics         xgress.Metrics
}

func NewXgressEnv(closeNotify <-chan struct{}, registry metrics.Registry) xgress.Env {
	return &xgEnv{
		payloadIngester: xgress.NewPayloadIngesterWithConfig(5, closeNotify),
		metrics:         xgress.NewMetrics(registry),
	}
}

func (x xgEnv) GetPayloadIngester() *xgress.PayloadIngester {
	return x.payloadIngester
}

func (x xgEnv) GetMetrics() xgress.Metrics {
	return x.metrics
}
