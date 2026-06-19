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
	"testing"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/metrics"
	"github.com/stretchr/testify/require"
)

// newTestEdgeRouter builds a SessionEdgeRouter with the given name, capability
// set, and a single advertised address (used as its latency-histogram key).
func newTestEdgeRouter(name, addr string, capabilities ...string) *rest_model.SessionEdgeRouter {
	er := &rest_model.SessionEdgeRouter{}
	er.Name = &name
	er.SupportedProtocols = map[string]string{"tls": addr}
	er.Capabilities = capabilities
	return er
}

func names(ers []*rest_model.SessionEdgeRouter) []string {
	result := make([]string, len(ers))
	for i, er := range ers {
		result[i] = *er.Name
	}
	return result
}

func TestFilterEdgeRoutersByCapability(t *testing.T) {
	req := require.New(t)

	ers := []*rest_model.SessionEdgeRouter{
		newTestEdgeRouter("a", "a:443", "CONNECT_V2", "STUN"),
		newTestEdgeRouter("b", "b:443", "CONNECT_V2"),
		newTestEdgeRouter("c", "c:443", "STUN"),
		newTestEdgeRouter("d", "d:443"), // no capabilities (e.g. predates the field)
	}

	req.Equal([]string{"a", "c"}, names(filterEdgeRoutersByCapability(ers, "STUN")))
	req.Equal([]string{"a", "b"}, names(filterEdgeRoutersByCapability(ers, "CONNECT_V2")))
	req.Empty(filterEdgeRoutersByCapability(ers, "MISSING"))
	req.Empty(filterEdgeRoutersByCapability(nil, "STUN"))
}

func TestEdgeRoutersForCapabilityRanksByLatency(t *testing.T) {
	req := require.New(t)

	reg := metrics.NewRegistry("test", nil)
	context := &ContextImpl{metrics: reg}

	// three STUN-capable routers; give b and c latency measurements (c faster),
	// leave a unmeasured (not connected). d is not STUN-capable.
	a := newTestEdgeRouter("a", "a:443", "STUN")
	b := newTestEdgeRouter("b", "b:443", "STUN")
	c := newTestEdgeRouter("c", "c:443", "STUN")
	d := newTestEdgeRouter("d", "d:443", "CONNECT_V2")

	reg.Histogram("latency.b:443").Update(50)
	reg.Histogram("latency.c:443").Update(10)

	ranked := context.edgeRoutersForCapability([]*rest_model.SessionEdgeRouter{a, b, c, d}, "STUN")

	// d filtered out (not STUN); measured c (10) before measured b (50) before
	// unmeasured a.
	req.Equal([]string{"c", "b", "a"}, names(ranked))
}
