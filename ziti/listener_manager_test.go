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
	"errors"
	"testing"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/openziti/sdk-golang/v2/ziti/edge/network"
	"github.com/stretchr/testify/require"
)

// bindCapturingRouterConn records the options of each Listen and refuses the bind.
type bindCapturingRouterConn struct {
	edge.RouterConn
	options []edge.ListenOptions
}

func (s *bindCapturingRouterConn) GetRouterName() string { return "router" }

func (s *bindCapturingRouterConn) Listen(_ *rest_model.ServiceDetail, _ *rest_model.SessionDetail, options *edge.ListenOptions, _ func() xgress.Env) (edge.RouterHostConn, error) {
	s.options = append(s.options, *options)
	return nil, errors.New("bind refused")
}

// A bind carries the cost and precedence most recently set on the listener, not the ones it was
// created with.
func Test_listenerManager_BindCarriesUpdatedCostAndPrecedence(t *testing.T) {
	req := require.New(t)
	serviceName := "svc"
	service := &rest_model.ServiceDetail{Name: &serviceName}
	options := &edge.ListenOptions{Cost: 3, Precedence: edge.PrecedenceDefault, ListenerId: "listener-id"}
	mgr := &listenerManager{
		service:   service,
		context:   &ContextImpl{closeNotify: make(chan struct{})},
		options:   options,
		listener:  network.NewMultiListener(service, options.Cost, options.Precedence, func() *rest_model.SessionDetail { return nil }),
		eventChan: make(chan listenerEvent, 1),
	}
	req.NoError(mgr.listener.UpdateCostAndPrecedence(7, edge.PrecedenceRequired))

	routerConn := &bindCapturingRouterConn{}
	mgr.createListener(routerConn, &rest_model.SessionDetail{}, 1)

	req.Len(routerConn.options, 1)
	bound := routerConn.options[0]
	req.Equal(uint16(7), bound.Cost)
	req.Equal(edge.PrecedenceRequired, bound.Precedence)
	req.Equal("listener-id", bound.ListenerId)
	req.Equal(uint16(3), options.Cost, "the manager's options are left unmodified")
}
