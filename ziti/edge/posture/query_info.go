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

package posture

import (
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
)

// QueryInfo describes the posture queries a submission destination requires: which query types are
// active, which process paths are watched, and the lowest MFA timeout among the destination's
// checks. It is the unit the cache uses to decide what posture data to collect and which responses
// a destination needs.
type QueryInfo struct {
	// QueryTypes maps an active posture query type to a representative query id for that type.
	QueryTypes map[string]string
	// Processes maps a watched process path to its owning query id.
	Processes map[string]string
	// TotpTimeout is the lowest MFA timeout among the destination's queries, or
	// TotpPostureCheckNoTimeout when no MFA query carries a timeout.
	TotpTimeout int64
}

// GetQueryInfo computes the posture query info the given active dial and bind services require,
// reading each service's PostureQueries (dial-policy queries for dial services, bind-policy
// queries for bind services).
func GetQueryInfo(dialServices, bindServices []*rest_model.ServiceDetail) *QueryInfo {
	queryTypes, processes, totpTimeout := getActiveQueryInfo(dialServices, bindServices)
	return &QueryInfo{
		QueryTypes:  queryTypes,
		Processes:   processes,
		TotpTimeout: totpTimeout,
	}
}

// isEmpty reports whether the info requires no posture data at all.
func (info *QueryInfo) isEmpty() bool {
	return len(info.QueryTypes) == 0 && len(info.Processes) == 0
}

// clone returns an independent copy of the info.
func (info *QueryInfo) clone() *QueryInfo {
	result := &QueryInfo{
		QueryTypes:  make(map[string]string, len(info.QueryTypes)),
		Processes:   make(map[string]string, len(info.Processes)),
		TotpTimeout: info.TotpTimeout,
	}
	for queryType, queryId := range info.QueryTypes {
		result.QueryTypes[queryType] = queryId
	}
	for path, queryId := range info.Processes {
		result.Processes[path] = queryId
	}
	return result
}

// merge folds other's query types and processes into info, keeping the lowest TOTP timeout of the
// two (TotpPostureCheckNoTimeout never wins over a real timeout).
func (info *QueryInfo) merge(other *QueryInfo) {
	for queryType, queryId := range other.QueryTypes {
		info.QueryTypes[queryType] = queryId
	}
	for path, queryId := range other.Processes {
		info.Processes[path] = queryId
	}
	if other.TotpTimeout != TotpPostureCheckNoTimeout &&
		(info.TotpTimeout == TotpPostureCheckNoTimeout || other.TotpTimeout < info.TotpTimeout) {
		info.TotpTimeout = other.TotpTimeout
	}
}

// RouterQueryInfoProvider supplies, per router connection, the posture query info that router's
// pushed state requires for the identity's active services. The bool is false when the SDK holds
// no per-router state for the connection (e.g. it is not push-subscribed); callers then fall back
// to the globally-derived query info.
type RouterQueryInfoProvider interface {
	GetRouterPostureQueryInfo(conn edge.RouterConn) (*QueryInfo, bool)
}
