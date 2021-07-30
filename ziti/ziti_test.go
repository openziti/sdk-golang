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
