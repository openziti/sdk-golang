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

package xgress

import (
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

const startTimeoutWarning = "xgress circuit not started in time, closing"

func newUnstartedTerminator(t *testing.T) *Xgress {
	closeNotify := make(chan struct{})
	conn := &testConn{ch: make(chan uint64, 1), closeNotify: make(chan struct{})}
	x := NewXgress("test", "ctrl", "test", conn, Terminator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{payloadIngester: NewPayloadIngester(closeNotify)}
	t.Cleanup(func() {
		x.Close()
		close(closeNotify)
	})
	return x
}

func countStartTimeoutWarnings(hook *logtest.Hook) int {
	count := 0
	for _, entry := range hook.AllEntries() {
		if entry.Message == startTimeoutWarning {
			count++
		}
	}
	return count
}

// TestTerminateIfNotStartedIgnoresClosedXgress covers the circuit start timer firing on a
// terminator whose circuit never started. An open xgress is closed with a warning; one that
// was already closed is left alone, without the warning.
func TestTerminateIfNotStartedIgnoresClosedXgress(t *testing.T) {
	req := require.New(t)
	hook := &logtest.Hook{}
	prevHooks := logrus.StandardLogger().ReplaceHooks(logrus.LevelHooks{})
	logrus.AddHook(hook)
	t.Cleanup(func() { logrus.StandardLogger().ReplaceHooks(prevHooks) })

	open := newUnstartedTerminator(t)
	open.terminateIfNotStarted()
	req.True(open.IsClosed())
	req.Equal(1, countStartTimeoutWarnings(hook))

	closed := newUnstartedTerminator(t)
	closed.Close()
	hook.Reset()
	closed.terminateIfNotStarted()
	req.Equal(0, countStartTimeoutWarnings(hook))
}
