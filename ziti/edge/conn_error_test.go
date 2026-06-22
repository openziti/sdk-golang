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
	"context"
	"errors"
	"testing"

	"github.com/openziti/channel/v5"
	"github.com/stretchr/testify/require"
)

// TestConnError_IsAndAs locks in the two matching idioms on one error value: errors.Is against
// the per-cause sentinels, errors.As for the typed details, and Unwrap pass-through for
// unrelated targets.
func TestConnError_IsAndAs(t *testing.T) {
	req := require.New(t)

	underlying := context.DeadlineExceeded
	var err error = &ConnError{
		ServiceName:   "ssh",
		ServiceId:     "svc-1",
		RouterName:    "er-east",
		RouterId:      "r-1",
		Cause:         CausePostureFailed,
		FailingChecks: []string{"chk-mfa"},
		Err:           underlying,
	}

	req.True(errors.Is(err, ErrPostureFailed), "sentinel must match the cause")
	req.False(errors.Is(err, ErrAccessDenied), "other sentinels must not match")
	req.True(errors.Is(err, context.DeadlineExceeded), "Unwrap must pass unrelated targets through")

	var connErr *ConnError
	req.True(errors.As(err, &connErr))
	req.Equal("svc-1", connErr.ServiceId)
	req.Equal("r-1", connErr.RouterId)
	req.Equal([]string{"chk-mfa"}, connErr.FailingChecks)

	msg := err.Error()
	req.Contains(msg, "posture check failed")
	req.Contains(msg, "svc-1")
	req.Contains(msg, "r-1")
	req.Contains(msg, "chk-mfa")
}

// TestConnRefusalError_ReadsStructuredError locks in the wire mapping: a StateClosed reply
// carrying the router's structured error yields the classified cause and the failing check ids;
// one without yields CauseUnknown with the message text preserved.
func TestConnRefusalError_ReadsStructuredError(t *testing.T) {
	req := require.New(t)

	structured := Error{
		Message:                "posture checks failed",
		Code:                   ErrorCodePostureCheckFailed,
		FailingPostureCheckIds: []string{"chk-1", "chk-2"},
	}
	reply := NewStateClosedMsg(1, structured.Message)
	structured.ApplyToMsg(reply)

	err := ConnRefusalError(reply, "ssh", "svc-1", "er-east", "r-1")
	req.True(errors.Is(err, ErrPostureFailed))
	var connErr *ConnError
	req.True(errors.As(err, &connErr))
	req.Equal([]string{"chk-1", "chk-2"}, connErr.FailingChecks)
	req.Equal("r-1", connErr.RouterId)

	// Access denied maps without check ids.
	denied := Error{Message: "no access", Code: ErrorCodeAccessDenied}
	deniedReply := NewStateClosedMsg(1, denied.Message)
	denied.ApplyToMsg(deniedReply)
	err = ConnRefusalError(deniedReply, "ssh", "svc-1", "er-east", "r-1")
	req.True(errors.Is(err, ErrAccessDenied))

	// An unknown service maps to service-not-available.
	invalidSvc := Error{Message: "service not found", Code: ErrorCodeInvalidService}
	invalidSvcReply := NewStateClosedMsg(1, invalidSvc.Message)
	invalidSvc.ApplyToMsg(invalidSvcReply)
	err = ConnRefusalError(invalidSvcReply, "ssh", "svc-1", "er-east", "r-1")
	req.True(errors.Is(err, ErrServiceNotAvailable))

	// A reply with no structured error stays CauseUnknown but keeps the text.
	bare := channel.NewMessage(ContentTypeStateClosed, []byte("boom"))
	err = ConnRefusalError(bare, "ssh", "svc-1", "er-east", "r-1")
	req.False(errors.Is(err, ErrPostureFailed))
	req.Contains(err.Error(), "boom")
}
