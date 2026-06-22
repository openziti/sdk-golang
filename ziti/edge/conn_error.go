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

package edge

import (
	"errors"
	"fmt"
	"strings"

	"github.com/openziti/channel/v5"
)

// FailureCause classifies why a dial or bind failed. Branch on ConnError.Cause after
// errors.As, or match the per-cause sentinels with errors.Is.
type FailureCause uint32

const (
	// CauseUnknown means the failure carried no recognized classification.
	CauseUnknown FailureCause = iota
	// CauseAccessDenied means no service policy grants the identity access.
	CauseAccessDenied
	// CausePostureFailed means policies grant access but their posture checks are failing;
	// ConnError.FailingChecks carries the failing check ids.
	CausePostureFailed
	// CauseSessionInvalid means the api session or service session was rejected.
	CauseSessionInvalid
	// CauseServiceNotAvailable means the service is unknown to the identity's current view.
	CauseServiceNotAvailable
	// CauseNoCapableRouter means no connected edge router could carry the attempt.
	CauseNoCapableRouter
)

func (c FailureCause) String() string {
	switch c {
	case CauseAccessDenied:
		return "access denied"
	case CausePostureFailed:
		return "posture check failed"
	case CauseSessionInvalid:
		return "session invalid"
	case CauseServiceNotAvailable:
		return "service not available"
	case CauseNoCapableRouter:
		return "no capable router"
	default:
		return "unknown"
	}
}

// Sentinel targets for errors.Is. They carry no data — use errors.As with *ConnError to extract
// the failure's details.
var (
	ErrAccessDenied        = errors.New("access denied")
	ErrPostureFailed       = errors.New("posture check failed")
	ErrSessionInvalid      = errors.New("session invalid")
	ErrServiceNotAvailable = errors.New("service not available")
	ErrNoCapableRouter     = errors.New("no capable router")
)

// ConnError is the typed failure a dial or bind returns: what was attempted (service, router)
// and why it failed. Match a kind with errors.Is (e.g. errors.Is(err, ErrPostureFailed)) or
// extract the details with errors.As.
type ConnError struct {
	// ServiceName and ServiceId identify the dialed or bound service.
	ServiceName string
	ServiceId   string

	// RouterName and RouterId identify the edge router that refused or failed the attempt.
	// Empty when the failure occurred before a router was involved.
	RouterName string
	RouterId   string

	// Cause classifies the failure.
	Cause FailureCause

	// FailingChecks carries the failing posture check ids when Cause is CausePostureFailed.
	FailingChecks []string

	// Err is the underlying cause, if any.
	Err error
}

var _ error = (*ConnError)(nil)

func (e *ConnError) Error() string {
	b := strings.Builder{}
	b.WriteString(e.Cause.String())
	if e.ServiceName != "" || e.ServiceId != "" {
		_, _ = fmt.Fprintf(&b, " for service %q (%s)", e.ServiceName, e.ServiceId)
	}
	if e.RouterName != "" || e.RouterId != "" {
		_, _ = fmt.Fprintf(&b, " on router %q (%s)", e.RouterName, e.RouterId)
	}
	if len(e.FailingChecks) > 0 {
		_, _ = fmt.Fprintf(&b, ", failing posture checks: %v", e.FailingChecks)
	}
	if e.Err != nil {
		_, _ = fmt.Fprintf(&b, ": %v", e.Err)
	}
	return b.String()
}

// Unwrap exposes the underlying cause so errors.Is/errors.As keep walking the chain.
func (e *ConnError) Unwrap() error {
	return e.Err
}

// Is maps sentinel comparisons onto the failure cause, so errors.Is(err, ErrPostureFailed)
// works without extracting the struct.
func (e *ConnError) Is(target error) bool {
	switch target {
	case ErrAccessDenied:
		return e.Cause == CauseAccessDenied
	case ErrPostureFailed:
		return e.Cause == CausePostureFailed
	case ErrSessionInvalid:
		return e.Cause == CauseSessionInvalid
	case ErrServiceNotAvailable:
		return e.Cause == CauseServiceNotAvailable
	case ErrNoCapableRouter:
		return e.Cause == CauseNoCapableRouter
	}
	return false
}

// failureCauseFromCode maps a structured error code from the router onto a FailureCause.
func failureCauseFromCode(code uint32) FailureCause {
	switch code {
	case ErrorCodeAccessDenied:
		return CauseAccessDenied
	case ErrorCodePostureCheckFailed:
		return CausePostureFailed
	case ErrorCodeInvalidApiSession, ErrorCodeInvalidSession, ErrorCodeWrongSessionType,
		ErrorCodeInvalidApiSessionType, ErrorCodeInvalidEdgeRouterForSession:
		return CauseSessionInvalid
	case ErrorCodeInvalidService:
		return CauseServiceNotAvailable
	default:
		return CauseUnknown
	}
}

// ConnRefusalError builds the typed error for a router's StateClosed refusal, reading the
// structured error (cause code + failing posture check ids) when the router sent one.
func ConnRefusalError(replyMsg *channel.Message, serviceName, serviceId, routerName, routerId string) error {
	connErr := &ConnError{
		ServiceName: serviceName,
		ServiceId:   serviceId,
		RouterName:  routerName,
		RouterId:    routerId,
		Cause:       CauseUnknown,
		Err:         errors.New(string(replyMsg.Body)),
	}
	if structured := ErrorFromMsg(replyMsg); structured != nil {
		connErr.Cause = failureCauseFromCode(structured.Code)
		connErr.FailingChecks = structured.FailingPostureCheckIds
	}
	return connErr
}
