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
	"math"
	"slices"
	"sort"
	"time"

	"github.com/openziti/edge-api/rest_model"
	metrics2 "github.com/rcrowley/go-metrics"
)

// edgeRouterHasCapability reports whether the edge router advertises the given
// capability. Edge routers that predate the capabilities field advertise none.
func edgeRouterHasCapability(er *rest_model.SessionEdgeRouter, capability string) bool {
	return slices.Contains(er.Capabilities, capability)
}

// filterEdgeRoutersByCapability returns the subset of ers that advertise the
// given capability, preserving input order. It lets a caller pick an edge
// router that supports a feature before connecting, with no speculative dials.
func filterEdgeRoutersByCapability(ers []*rest_model.SessionEdgeRouter, capability string) []*rest_model.SessionEdgeRouter {
	var result []*rest_model.SessionEdgeRouter
	for _, er := range ers {
		if edgeRouterHasCapability(er, capability) {
			result = append(result, er)
		}
	}
	return result
}

// edgeRoutersForCapability returns the service edge routers that advertise the
// given capability, ordered by measured latency (lowest first). Edge routers
// with a latency measurement (currently connected) sort ahead of those without
// one; among unmeasured routers, input order is preserved. Feature code (p2p
// STUN selection, rerouting takeover-candidate selection) uses this to choose
// a capable router before connecting.
func (context *ContextImpl) edgeRoutersForCapability(ers []*rest_model.SessionEdgeRouter, capability string) []*rest_model.SessionEdgeRouter {
	filtered := filterEdgeRoutersByCapability(ers, capability)
	sort.SliceStable(filtered, func(i, j int) bool {
		li, oki := context.measuredLatency(filtered[i])
		lj, okj := context.measuredLatency(filtered[j])
		if oki != okj {
			return oki // a measured router sorts ahead of an unmeasured one
		}
		if !oki {
			return false // neither measured: keep input order
		}
		return li < lj
	})
	return filtered
}

// measuredLatency returns the best measured latency across the edge router's
// advertised addresses, and whether any measurement exists. Only connected
// routers have a latency histogram, so an unconnected router reports false.
func (context *ContextImpl) measuredLatency(er *rest_model.SessionEdgeRouter) (time.Duration, bool) {
	best := time.Duration(math.MaxInt64)
	found := false
	for _, addr := range er.SupportedProtocols {
		if h, ok := context.metrics.GetHistogram("latency." + addr).(metrics2.Histogram); ok && h.Count() > 0 {
			if d := time.Duration(int64(h.Mean())); d < best {
				best = d
				found = true
			}
		}
	}
	return best, found
}
