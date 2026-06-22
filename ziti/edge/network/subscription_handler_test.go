/*
	Copyright NetFoundry Inc.

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

package network

import (
	"sync"
	"testing"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
)

var _ edge.ServiceSubscriptionHandler = noopSubscriptionHandler{}

type noopSubscriptionHandler struct{}

func (noopSubscriptionHandler) HandleServiceChangeSet(edge.RouterConn, *channel.Message)   {}
func (noopSubscriptionHandler) HandlePostureStateChange(edge.RouterConn, *channel.Message) {}

// TestRouterConnSubscriptionHandlerRace exercises concurrent registration and delivery of the
// service subscription handler. Registration (SetServiceSubscriptionHandler) runs on the caller's
// goroutine while delivery runs on the channel receive pool, so the handler field must be
// synchronized. Run with -race to detect a regression.
func TestRouterConnSubscriptionHandlerRace(t *testing.T) {
	conn := &routerConn{}
	handler := noopSubscriptionHandler{}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); conn.SetServiceSubscriptionHandler(handler) }()
		go func() { defer wg.Done(); conn.handleServiceChangeSet(nil, nil) }()
		go func() { defer wg.Done(); conn.handlePostureStateChange(nil, nil) }()
	}
	wg.Wait()
}
