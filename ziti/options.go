package ziti

import (
	"github.com/openziti/edge-api/rest_model"
	"time"
)

type ServiceEventType string

const (
	ServiceAdded   ServiceEventType = "Added"
	ServiceRemoved ServiceEventType = "Removed"
	ServiceChanged ServiceEventType = "Changed"

	DefaultServiceRefreshInterval = 5 * time.Minute
	DefaultSessionRefreshInterval = time.Hour
	MinRefreshInterval            = time.Second
)

type serviceCB func(eventType ServiceEventType, service *rest_model.ServiceDetail)

type Options struct {
	// Service refresh interval. May not be less than 1 second
	RefreshInterval time.Duration

	// Edge session refresh interval. Edge session only need to be refreshed if the list of available
	// edge routers has changed. This should be a relatively rare occurrence. If a dial fails, the
	// edge session will be refreshed regardless.
	// May not be less than 1 second
	SessionRefreshInterval time.Duration

	// Deprecated: OnContextReady is a callback that is invoked after the first successful authentication request. It
	// does not delineate between fully and partially authenticated API Sessions. Use context.AddListener() with the events
	// EventAuthenticationStateFull, EventAuthenticationStatePartial, EventAuthenticationStateUnAuthenticated instead.
	OnContextReady func(ctx Context)

	// Deprecated: OnServiceUpdate is a callback that is invoked when a service changes its definition.
	// Use `zitiContext.AddListener(<eventName>, handler)` where `eventName` may be EventServiceAdded, EventServiceChanged, EventServiceRemoved.
	OnServiceUpdate     serviceCB
	EdgeRouterUrlFilter func(string) bool
}

func (self *Options) isEdgeRouterUrlAccepted(url string) bool {
	return self.EdgeRouterUrlFilter == nil || self.EdgeRouterUrlFilter(url)
}

var DefaultOptions = &Options{
	RefreshInterval:        DefaultServiceRefreshInterval,
	SessionRefreshInterval: DefaultSessionRefreshInterval,
	OnServiceUpdate:        nil,
}

type DialOptions struct {
	ConnectTimeout time.Duration
	Identity       string
	AppData        []byte
}

func (d DialOptions) GetConnectTimeout() time.Duration {
	return d.ConnectTimeout
}

type ListenOptions struct {
	Cost                         uint16
	Precedence                   Precedence
	ConnectTimeout               time.Duration
	MaxConnections               int
	Identity                     string
	BindUsingEdgeIdentity        bool
	ManualStart                  bool
	WaitForNEstablishedListeners uint
}

func DefaultListenOptions() *ListenOptions {
	return &ListenOptions{
		Cost:           0,
		Precedence:     PrecedenceDefault,
		ConnectTimeout: 5 * time.Second,
		MaxConnections: 3,
	}
}
