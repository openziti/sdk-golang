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

import "github.com/openziti/sdk-golang/v2/ziti/edge"

// ConnError is the typed failure a dial or bind returns: what was attempted (service, router
// name and id) and why it failed. Extract it with errors.As, or match a failure kind with
// errors.Is against the Err* sentinels.
type ConnError = edge.ConnError

// FailureCause classifies a ConnError; see the Cause* constants.
type FailureCause = edge.FailureCause

const (
	CauseUnknown             = edge.CauseUnknown
	CauseAccessDenied        = edge.CauseAccessDenied
	CausePostureFailed       = edge.CausePostureFailed
	CauseSessionInvalid      = edge.CauseSessionInvalid
	CauseServiceNotAvailable = edge.CauseServiceNotAvailable
	CauseNoCapableRouter     = edge.CauseNoCapableRouter
)

// Sentinel targets for errors.Is; use errors.As with *ConnError for the failure's details.
var (
	ErrAccessDenied        = edge.ErrAccessDenied
	ErrPostureFailed       = edge.ErrPostureFailed
	ErrSessionInvalid      = edge.ErrSessionInvalid
	ErrServiceNotAvailable = edge.ErrServiceNotAvailable
	ErrNoCapableRouter     = edge.ErrNoCapableRouter
)
