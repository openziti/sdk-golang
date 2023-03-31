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
)

type serviceCB func(eventType ServiceEventType, service *rest_model.ServiceDetail)

type Options struct {
	RefreshInterval time.Duration
	OnContextReady  func(ctx Context)
	OnServiceUpdate serviceCB
}

var DefaultOptions = &Options{
	RefreshInterval: 5 * time.Minute,
	OnServiceUpdate: nil,
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
	Cost                  uint16
	Precedence            Precedence
	ConnectTimeout        time.Duration
	MaxConnections        int
	Identity              string
	BindUsingEdgeIdentity bool
	ManualStart           bool
}

func DefaultListenOptions() *ListenOptions {
	return &ListenOptions{
		Cost:           0,
		Precedence:     PrecedenceDefault,
		ConnectTimeout: 5 * time.Second,
		MaxConnections: 3,
	}
}
