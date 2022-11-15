package ziti

import (
	"fmt"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/posture"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

func Test_contextImpl_processServiceUpdates(t *testing.T) {

	callbacks := make(map[string]ServiceEventType)
	servUpdate := func(eventType ServiceEventType, service *edge.Service) {
		println(eventType, service.Name)
		callbacks[service.Name] = eventType
	}

	closeNotify := make(chan struct{})
	defer close(closeNotify)

	ctx := &contextImpl{
		options: &Options{
			OnServiceUpdate: servUpdate,
		},
		services:     sync.Map{},
		sessions:     sync.Map{},
		postureCache: posture.NewCache(nil, closeNotify),
	}

	var services []*edge.Service

	for i := 0; i < 5; i++ {
		services = append(services, &edge.Service{
			Id:   fmt.Sprint("serviceId - ", i),
			Name: fmt.Sprint("service", i),
		})
	}

	ctx.processServiceUpdates(services)

	assert.Equal(t, len(services), len(callbacks))
	for _, s := range services {
		assert.Contains(t, callbacks, s.Name)
	}

	callbacks = make(map[string]ServiceEventType)
	ctx.processServiceUpdates(services)
	assert.Empty(t, callbacks)

	// remove one
	ctx.processServiceUpdates(services[1:])
	assert.Equal(t, 1, len(callbacks))
	assert.Equal(t, ServiceRemoved, callbacks[services[0].Name])
	_, found := ctx.services.Load(services[0].Name)
	assert.False(t, found)

	callbacks = make(map[string]ServiceEventType)

	// remove the rest
	ctx.processServiceUpdates(nil)
	assert.Equal(t, len(services)-1, len(callbacks))
	for _, v := range callbacks {
		assert.Equal(t, ServiceRemoved, v)
	}
	ctx.services.Range(func(key, value interface{}) bool {
		assert.Fail(t, "should be empty")
		return true
	})

	// test changes
	ctx.processServiceUpdates(services)

	updates := []*edge.Service{
		{
			Name:        services[0].Name,
			Id:          services[0].Id,
			Permissions: []string{"Dial"},
		},
	}
	callbacks = make(map[string]ServiceEventType)
	ctx.processServiceUpdates(updates)

	assert.Equal(t, len(services), len(callbacks))
	assert.Equal(t, ServiceChanged, callbacks[services[0].Name])
}

func Test_AddressMatch(t *testing.T) {

	http := edge.PortRange{80, 80}
	https := edge.PortRange{443, 443}
	privPorts := edge.PortRange{0, 1024}

	hostname, _ := edge.NewZitiAddress("plain.host.ziti")
	domain, _ := edge.NewZitiAddress("*.domain.ziti")
	ipaddr, _ := edge.NewZitiAddress("100.64.255.1")
	cidr, _ := edge.NewZitiAddress("100.64.0.0/10")

	services := []*edge.Service{
		{
			Id:   "httpByHostname",
			Name: "httpByHostname",
			Configs: map[string]map[string]interface{}{
				edge.InterceptV1: {
					"protocols":  []string{"tcp"},
					"addresses":  []*edge.ZitiAddress{hostname},
					"portRanges": []edge.PortRange{http, https},
				},
			},
		},
		{
			Id:   "httpByDomain",
			Name: "httpByDomain",
			Configs: map[string]map[string]interface{}{
				edge.InterceptV1: {
					"protocols":  []string{"tcp"},
					"addresses":  []*edge.ZitiAddress{domain},
					"portRanges": []edge.PortRange{http, https},
				},
			},
		},
		{
			Id:   "adminByDomain",
			Name: "adminByDomain",
			Configs: map[string]map[string]interface{}{
				edge.InterceptV1: {
					"protocols":  []string{"tcp", "udp"},
					"addresses":  []*edge.ZitiAddress{domain},
					"portRanges": []edge.PortRange{privPorts},
				},
			},
		},
		{
			Id:   "httpByIP",
			Name: "httpByIP",
			Configs: map[string]map[string]interface{}{
				edge.InterceptV1: {
					"protocols":  []string{"tcp"},
					"addresses":  []*edge.ZitiAddress{ipaddr},
					"portRanges": []edge.PortRange{http},
				},
			},
		},
		{
			Id:   "adminByCidr",
			Name: "adminByCidr",
			Configs: map[string]map[string]interface{}{
				edge.InterceptV1: {
					"protocols":  []string{"tcp", "udp"},
					"addresses":  []*edge.ZitiAddress{cidr},
					"portRanges": []edge.PortRange{privPorts},
				},
			},
		},
	}

	ctx := &contextImpl{
		options:      &Options{},
		services:     sync.Map{},
		sessions:     sync.Map{},
		intercepts:   sync.Map{},
		postureCache: posture.NewCache(nil, nil),
	}
	ctx.processServiceUpdates(services)

	type args struct {
		Network  string
		Hostname string
		Port     uint16
	}

	cases := []struct {
		params   args
		expected int
		name     string
	}{
		{params: args{Network: "udp", Hostname: "plain.host.ziti", Port: 80}, expected: -1},
		{params: args{Network: "tcp", Hostname: "plain.host.ziti", Port: 80}, expected: 0, name: "httpByHostname"},

		{params: args{Network: "tcp", Hostname: "foo.domain.ziti", Port: 80}, expected: 3 << 16, name: "httpByDomain"},
		{params: args{Network: "tcp", Hostname: "foo.host.notziti", Port: 80}, expected: -1},

		{params: args{Network: "udp", Hostname: "bar.domain.ziti", Port: 22}, expected: int(3<<16 | 1024), name: "adminByDomain"},
		{params: args{Network: "tcp", Hostname: "100.64.255.1", Port: 80}, expected: 0, name: "httpByIP"},

		{params: args{Network: "tcp", Hostname: "100.64.255.1", Port: 443}, expected: (32-10)<<16 | 1024, name: "adminByCidr"},
		{params: args{Network: "tcp", Hostname: "100.64.0.1", Port: 80}, expected: (32-10)<<16 | 1024, name: "adminByCidr"},
		{params: args{Network: "tcp", Hostname: "100.64.10.1", Port: 1443}, expected: -1},
	}

	check := assert.New(t)

	for _, c := range cases {
		srv, score, err := ctx.GetServiceForAddr(c.params.Network, c.params.Hostname, c.params.Port)
		if c.expected == -1 {
			check.Error(err, "should get error", c.params)
		} else {
			check.NoError(err, "unexpected error", c.params)
			check.Equal(c.expected, score, "score", c.params)
			check.Equal(c.name, srv.Name, c.params)
		}

	}
}
