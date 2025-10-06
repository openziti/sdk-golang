package posture

import (
	"fmt"

	"github.com/openziti/edge-api/rest_model"
	edge_apis "github.com/openziti/sdk-golang/edge-apis"
	"github.com/openziti/sdk-golang/ziti/edge"
)

type Submitter interface {
	SendPostureResponse(response rest_model.PostureResponseCreate) error
	SendPostureResponseBulk(responses []rest_model.PostureResponseCreate) error
}

type RouterConnectionProvider interface {
	GetRouterConnections() []edge.RouterConn
}

type ApiSessionProvider interface {
	GetCurrentApiSession() edge_apis.ApiSession
}

var _ Submitter = (*MultiSubmitter)(nil)

// MultiSubmitter submits posture responses to multiple destinations. Those destinations are determined by the
// nature of the API Session and router connections. Legacy, non-HA, API Sessions will always send to the controller.
// HA API Sessions will send to the controller if the router does not support posture checks. HA API Sessions must
// send to routers that support posture checks.
type MultiSubmitter struct {
	ApiSessionProvider       ApiSessionProvider
	LegacySubmitter          Submitter
	RouterConnectionProvider RouterConnectionProvider
}

func NewMultiSubmitter(apiSessionProvider ApiSessionProvider, legacySubmitter Submitter, routerConnectionProvider RouterConnectionProvider) *MultiSubmitter {
	return &MultiSubmitter{
		ApiSessionProvider:       apiSessionProvider,
		LegacySubmitter:          legacySubmitter,
		RouterConnectionProvider: routerConnectionProvider,
	}
}

func (m *MultiSubmitter) SendPostureResponse(response rest_model.PostureResponseCreate) error {
	if response == nil {
		return nil
	}
	return m.SendPostureResponseBulk([]rest_model.PostureResponseCreate{response})
}

func (m *MultiSubmitter) SendPostureResponseBulk(responses []rest_model.PostureResponseCreate) error {
	if len(responses) == 0 {
		return nil
	}
	
	apiSession := m.ApiSessionProvider.GetCurrentApiSession()

	//legacy api sessions do not use router posture always goes to the controller
	if apiSession.GetType() == edge_apis.ApiSessionTypeLegacy {
		return m.LegacySubmitter.SendPostureResponseBulk(responses)
	}

	sendToController := false

	routerConns := m.RouterConnectionProvider.GetRouterConnections()
	errors := &MultiDestinationError{
		routerErrors:    map[edge.RouterConn]error{},
		controllerError: nil,
	}

	for _, routerConn := range routerConns {
		if routerConn.GetBoolHeader(edge.SupportsPostureChecks) {
			err := routerConn.SendPosture(responses)
			if err != nil {
				errors.routerErrors[routerConn] = err
			}
		} else {
			sendToController = true
		}
	}

	if sendToController {
		errors.controllerError = m.LegacySubmitter.SendPostureResponseBulk(responses)

	}

	if errors.HasErrors() {
		return errors
	}

	return nil
}

type MultiDestinationError struct {
	routerErrors    map[edge.RouterConn]error
	controllerError error
}

func (e *MultiDestinationError) Error() string {
	result := ""

	if !e.HasErrors() {
		if e == nil {
			return ""
		}
		panic("unexpected error state, there are no errors, but treated as an error")
	}

	if e.controllerError != nil {
		result = "failed to send posture response to controller: " + e.controllerError.Error()
	}

	if len(e.routerErrors) > 0 {
		if result != "" {
			result += " and "
		}

		routerErrStr := ""

		for routerConn, err := range e.routerErrors {
			if routerErrStr != "" {
				routerErrStr += ", "
			}

			routerErrStr = routerErrStr + fmt.Sprintf("router [%s]: %s", routerConn.GetRouterName(), err.Error())
		}

		result = result + fmt.Sprintf("failed to send posture response to %d routers: %s", len(e.routerErrors), routerErrStr)
	}

	return result
}

func (e *MultiDestinationError) HasErrors() bool {
	return len(e.routerErrors) > 0 || e.controllerError != nil
}
