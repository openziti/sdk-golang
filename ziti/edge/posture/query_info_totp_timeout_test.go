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
	"fmt"
	"testing"

	"github.com/openziti/edge-api/rest_model"
	"github.com/stretchr/testify/require"
)

// mfaService builds a service whose dial policy carries one MFA posture query per supplied
// timeout, in the order given.
func mfaService(name string, timeouts ...int64) *rest_model.ServiceDetail {
	queryType := rest_model.PostureCheckTypeMFA

	var queries []*rest_model.PostureQuery
	for i := range timeouts {
		id := fmt.Sprintf("%s-mfa-%d", name, i)
		timeout := timeouts[i]
		query := &rest_model.PostureQuery{QueryType: &queryType, Timeout: &timeout}
		query.ID = &id
		queries = append(queries, query)
	}

	policyId := name + "-dial-policy"
	svc := &rest_model.ServiceDetail{}
	svc.PostureQueries = []*rest_model.PostureQueries{
		{
			PolicyID:       &policyId,
			PolicyType:     rest_model.DialBindDial,
			PostureQueries: queries,
		},
	}
	return svc
}

// TestGetQueryInfoTotpTimeoutIgnoresNoTimeoutSentinel locks in the rule QueryInfo.merge already
// states, that TotpPostureCheckNoTimeout never wins over a real timeout, for the timeouts gathered
// off the services themselves. TotpPostureCheckNoTimeout is -1, so a plain "lowest wins" compare
// lets a check with no timeout displace one that has a real timeout, and the surviving value then
// turns off the cache's proactive TOTP refresh for every check in the pass.
func TestGetQueryInfoTotpTimeoutIgnoresNoTimeoutSentinel(t *testing.T) {
	t.Run("no timeout after a real timeout, same service", func(t *testing.T) {
		info := GetQueryInfo([]*rest_model.ServiceDetail{
			mfaService("svc", 300, TotpPostureCheckNoTimeout),
		}, nil)
		require.Equal(t, int64(300), info.TotpTimeout)
	})

	t.Run("no timeout after a real timeout, separate services", func(t *testing.T) {
		info := GetQueryInfo([]*rest_model.ServiceDetail{
			mfaService("timed", 300),
			mfaService("untimed", TotpPostureCheckNoTimeout),
		}, nil)
		require.Equal(t, int64(300), info.TotpTimeout)
	})

	t.Run("order does not change the answer", func(t *testing.T) {
		forward := GetQueryInfo([]*rest_model.ServiceDetail{
			mfaService("svc", 300, TotpPostureCheckNoTimeout),
		}, nil)
		reverse := GetQueryInfo([]*rest_model.ServiceDetail{
			mfaService("svc", TotpPostureCheckNoTimeout, 300),
		}, nil)
		require.Equal(t, reverse.TotpTimeout, forward.TotpTimeout)
	})

	t.Run("lowest real timeout still wins", func(t *testing.T) {
		info := GetQueryInfo([]*rest_model.ServiceDetail{
			mfaService("svc", 300, 120, 600),
		}, nil)
		require.Equal(t, int64(120), info.TotpTimeout)
	})

	t.Run("all checks untimed stays untimed", func(t *testing.T) {
		info := GetQueryInfo([]*rest_model.ServiceDetail{
			mfaService("svc", TotpPostureCheckNoTimeout, TotpPostureCheckNoTimeout),
		}, nil)
		require.Equal(t, TotpPostureCheckNoTimeout, info.TotpTimeout)
	})
}
