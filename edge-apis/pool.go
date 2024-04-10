/*
	Copyright 2019 NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package edge_apis

import (
	"github.com/go-openapi/runtime"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pkg/errors"
	"golang.org/x/exp/rand"
	"net"
	"net/url"
	"sync/atomic"
	"time"
)

// ClientTransportPool abstracts the concept of multiple `runtime.ClientTransport` (openapi interface) representing one
// target OpenZiti network. In situations where controllers are running in HA mode (multiple controllers) this
// interface can attempt to try different controller during outages or partitioning.
type ClientTransportPool interface {
	runtime.ClientTransport

	Add(apiUrl *url.URL, transport runtime.ClientTransport)
	Remove(apiUrl *url.URL)
}

var _ runtime.ClientTransport = (ClientTransportPool)(nil)

// ClientTransportPoolRandom selects a client transport (controller) at random until it is unreachable. Controllers
// are tried at random until a controller is reached. The newly connected controller is set for use on future requests
// until is too becomes unreachable.
type ClientTransportPoolRandom struct {
	pool cmap.ConcurrentMap[string, runtime.ClientTransport]

	current atomic.Pointer[keyedClientTransport]
}

func NewClientTransportPoolRandom() *ClientTransportPoolRandom {
	return &ClientTransportPoolRandom{
		pool:    cmap.New[runtime.ClientTransport](),
		current: atomic.Pointer[keyedClientTransport]{},
	}
}

type keyedClientTransport struct {
	runtime.ClientTransport
	key string
}

func (c *ClientTransportPoolRandom) setCurrent(key string, transport runtime.ClientTransport) {
	c.current.Store(&keyedClientTransport{
		ClientTransport: transport,
		key:             key,
	})
}

func (c *ClientTransportPoolRandom) Add(apiUrl *url.URL, transport runtime.ClientTransport) {

	c.pool.Set(apiUrl.String(), transport)
}

func (c *ClientTransportPoolRandom) Remove(apiUrl *url.URL) {
	c.pool.Remove(apiUrl.String())
}

func (c *ClientTransportPoolRandom) Submit(operation *runtime.ClientOperation) (interface{}, error) {
	current := c.current.Load()
	key := ""

	if current != nil {
		key = current.key
		result, err := (*current).Submit(operation)

		if err == nil || !isNetworkError(err) {
			return result, err
		}

		if c.pool.Count() == 1 {
			return result, err
		}
	}

	if c.pool.Count() == 0 {
		return nil, errors.New("no client transport available")
	}

	return c.tryRandom(key, operation)
}

func (c *ClientTransportPoolRandom) tryRandom(failed string, operation *runtime.ClientOperation) (interface{}, error) {
	var curTransTpl *cmap.Tuple[string, runtime.ClientTransport]
	var lastResult any
	var lastErr error
	var transportTpls []*cmap.Tuple[string, runtime.ClientTransport]

	for tpl := range c.pool.IterBuffered() {
		if tpl.Key != failed {
			transportTpls = append(transportTpls, &tpl)
		}
	}

	for len(transportTpls) > 0 {
		curTransTpl, transportTpls = selectAndRemoveRandom(transportTpls, nil)
		lastResult, lastErr = curTransTpl.Val.Submit(operation)

		if lastErr == nil || !isNetworkError(lastErr) {
			c.setCurrent(curTransTpl.Key, curTransTpl.Val)
			return lastResult, lastErr
		}
	}

	return lastResult, lastErr
}

var _ runtime.ClientTransport = (*ClientTransportPoolRandom)(nil)
var _ ClientTransportPool = (*ClientTransportPoolRandom)(nil)

func isNetworkError(err error) bool {
	return errors.Is(err, &net.OpError{})
}

func selectAndRemoveRandom[T any](slice []T, zero T) (selected T, modifiedSlice []T) {
	rand.Seed(uint64(time.Now().UnixNano()))
	if len(slice) == 0 {
		return zero, slice
	}
	index := rand.Intn(len(slice))
	selected = slice[index]
	modifiedSlice = append(slice[:index], slice[index+1:]...)
	return selected, modifiedSlice
}
