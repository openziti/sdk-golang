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

package ziti

import (
	"net/url"
	"testing"

	"github.com/kataras/go-events"
	"github.com/stretchr/testify/require"
)

// TestControllerUrlsUpdateListenerRemoval pins the remover returned by
// AddControllerUrlsUpdateListener to the event it registered for: it previously
// removed the listener from EventAuthenticationStateUnauthenticated instead, so
// the urls listener was never unregistered and kept firing after removal.
func TestControllerUrlsUpdateListenerRemoval(t *testing.T) {
	req := require.New(t)
	ctx := &ContextImpl{EventEmmiter: events.New()}

	var received [][]*url.URL
	remove := ctx.AddControllerUrlsUpdateListener(func(_ Context, urls []*url.URL) {
		received = append(received, urls)
	})

	urls := []*url.URL{{Scheme: "https", Host: "ctrl1:1280"}}
	ctx.Emit(EventControllerUrlsUpdated, urls)
	req.Len(received, 1, "listener fires while registered")
	req.Equal(urls, received[0])

	remove()
	ctx.Emit(EventControllerUrlsUpdated, urls)
	req.Len(received, 1, "listener must not fire after its remover runs")
}
