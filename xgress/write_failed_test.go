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
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/openziti/channel/v4"
	"github.com/stretchr/testify/require"
)

// recordingConn records every WritePayload and signals when the xgress tx loop has finished.
type recordingConn struct {
	lock        sync.Mutex
	writes      [][]byte
	txDone      chan struct{}
	txDoneOnce  sync.Once
	closeNotify chan struct{}
	closeOnce   sync.Once
}

func newRecordingConn() *recordingConn {
	return &recordingConn{
		txDone:      make(chan struct{}),
		closeNotify: make(chan struct{}),
	}
}

func (self *recordingConn) Close() error {
	self.closeOnce.Do(func() { close(self.closeNotify) })
	return nil
}

func (self *recordingConn) LogContext() string {
	return "recording"
}

func (self *recordingConn) ReadPayload() ([]byte, map[uint8][]byte, error) {
	<-self.closeNotify
	return nil, nil, ErrPeerClosed
}

func (self *recordingConn) WritePayload(data []byte, _ map[uint8][]byte) (int, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.writes = append(self.writes, append([]byte{}, data...))
	return len(data), nil
}

func (self *recordingConn) HandleControlMsg(ControlType, channel.Headers, ControlReceiver) error {
	return nil
}

func (self *recordingConn) FlowFromFabricToXgressClosed() {
	self.txDoneOnce.Do(func() { close(self.txDone) })
}

func (self *recordingConn) getWrites() [][]byte {
	self.lock.Lock()
	defer self.lock.Unlock()
	return self.writes
}

// overLink returns payload as a link delivers it: marshalled to the channel wire format and
// decoded again.
func overLink(t *testing.T, payload *Payload) *Payload {
	encoded, err := channel.MarshalV2(payload.Marshall())
	require.NoError(t, err)
	msg, err := channel.ReadV2(bytes.NewReader(encoded))
	require.NoError(t, err)
	result, err := UnmarshallPayload(msg)
	require.NoError(t, err)
	return result
}

func TestWriteFailedPayloadIsNotWrittenToPeer(t *testing.T) {
	req := require.New(t)

	ingesterClose := make(chan struct{})
	defer close(ingesterClose)

	conn := newRecordingConn()
	x := NewXgress("test", "ctrl", "test", conn, Initiator, DefaultOptions(), nil)
	x.dataPlane = noopReceiveHandler{payloadIngester: NewPayloadIngester(ingesterClose)}
	go x.tx()
	defer x.Close()

	payloads := []*Payload{
		{CircuitId: "test", Flags: SetOriginatorFlag(0, Terminator), Sequence: 0, Data: []byte("echoed")},
		{CircuitId: "test", Flags: SetOriginatorFlag(uint32(PayloadFlagWriteFailed), Terminator), Sequence: 1},
		{CircuitId: "test", Flags: SetOriginatorFlag(uint32(PayloadFlagEOF), Terminator), Sequence: 2},
	}

	for _, payload := range payloads {
		req.NoError(x.SendPayload(overLink(t, payload), 0, PayloadTypeXg))
	}

	select {
	case <-conn.txDone:
	case <-time.After(5 * time.Second):
		req.Fail("tx loop did not finish")
	}

	req.Equal([][]byte{[]byte("echoed")}, conn.getWrites())
}
