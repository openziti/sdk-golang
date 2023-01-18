package ziti

import (
	"context"
	"fmt"
	"github.com/openziti/edge-api/rest_model"
	"math"
	"net"
	"strconv"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type dialer struct {
	fallback Dialer
	context  context.Context
}

func (dialer *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer.context = ctx
	return dialer.Dial(network, address)
}

func (dialer *dialer) Dial(network, address string) (net.Conn, error) {
	host, portstr, err := net.SplitHostPort(address)

	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, err
	}

	network = normalizeProtocol(network)

	var ztx Context
	var service *rest_model.ServiceDetail
	best := math.MaxInt
	ForAllContexts(func(ctx Context) bool {
		srv, score, err := ctx.GetServiceForAddr(network, host, uint16(port))
		if err == nil {
			if score < best {
				best = score
				ztx = ctx
				service = srv
			}

			if score == 0 { // best possible score
				return false
			}
		}
		return true
	})

	if ztx != nil && service != nil {
		return ztx.(*ContextImpl).dialServiceFromAddr(*service.Name, network, host, uint16(port))
	}

	if dialer.fallback != nil {
		ctxDialer, ok := dialer.fallback.(ContextDialer)
		if ok && dialer.context != nil {
			return ctxDialer.DialContext(dialer.context, network, address)
		} else {
			return dialer.fallback.Dial(network, address)
		}
	}

	return nil, fmt.Errorf("address [%s:%s:%d] is not intercepted by any ziti context", network, host, port)
}

func NewDialer() Dialer {
	return &dialer{}
}

func NewDialerWithFallback(ctx context.Context, fallback Dialer) Dialer {
	if fallback == nil {
		fallback = &net.Dialer{}
	}
	return &dialer{
		fallback: fallback,
		context:  ctx,
	}
}

func normalizeProtocol(proto string) string {
	switch proto {
	case "tcp", "tcp4", "tcp6":
		return "tcp"
	case "udp", "udp4", "udp6":
		return "udp"
	default:
		return proto
	}
}
