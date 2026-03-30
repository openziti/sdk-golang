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
	"time"

	"github.com/stretchr/testify/require"
)

func TestRttSpikeCap(t *testing.T) {
	req := require.New(t)
	opts := DefaultOptions()

	conn := &testConn{closeNotify: make(chan struct{})}
	x := NewXgress("test", "ctrl", "test", conn, Initiator, opts, nil)
	x.dataPlane = noopReceiveHandler{payloadIngester: NewPayloadIngester(make(chan struct{}))}
	buf := NewLinkSendBuffer(x)

	// Feed stable 50ms samples to establish baseline
	for i := 0; i < 10; i++ {
		seq := int32(i)
		payload := &Payload{CircuitId: "test", Sequence: seq, Data: make([]byte, 100)}
		buf.buffer[seq] = &txPayload{payload: payload, x: x, age: time.Now().UnixMilli()}

		rttStamp := uint16(time.Now().UnixMilli()) - uint16(50)
		ack := &Acknowledgement{
			CircuitId:      "test",
			Sequence:       []int32{seq},
			RTT:            rttStamp,
			RecvBufferSize: 1024 * 1024,
		}
		buf.receiveAcknowledgement(ack)
	}

	baselineThreshold := buf.retxThreshold
	t.Logf("baseline: lastRtt=%d, retxThreshold=%d", buf.lastRtt, buf.retxThreshold)

	// Inject a massive spike (53,000ms wrapped as uint16)
	// With MaxRttScale=4, the spike should be capped to 4*lastRtt
	seq := int32(10)
	payload := &Payload{CircuitId: "test", Sequence: seq, Data: make([]byte, 100)}
	buf.buffer[seq] = &txPayload{payload: payload, x: x, age: time.Now().UnixMilli()}

	rttStamp := uint16(time.Now().UnixMilli()) - uint16(53000)
	ack := &Acknowledgement{
		CircuitId:      "test",
		Sequence:       []int32{seq},
		RTT:            rttStamp,
		RecvBufferSize: 1024 * 1024,
	}
	buf.receiveAcknowledgement(ack)

	t.Logf("after spike: lastRtt=%d, retxThreshold=%d", buf.lastRtt, buf.retxThreshold)

	// retxThreshold should not have exploded — should stay under 1 second
	req.Less(buf.retxThreshold, uint32(1000),
		"retxThreshold should stay under 1s after a single capped spike")

	// Should be within a reasonable range of the baseline
	req.Less(buf.retxThreshold, baselineThreshold*4,
		"retxThreshold should not grow more than 4x from a single spike")
}

func TestRttSpikeCap_Recovery(t *testing.T) {
	req := require.New(t)
	opts := DefaultOptions()

	conn := &testConn{closeNotify: make(chan struct{})}
	x := NewXgress("test", "ctrl", "test", conn, Initiator, opts, nil)
	x.dataPlane = noopReceiveHandler{payloadIngester: NewPayloadIngester(make(chan struct{}))}
	buf := NewLinkSendBuffer(x)

	// Establish baseline at 50ms
	for i := 0; i < 10; i++ {
		seq := int32(i)
		payload := &Payload{CircuitId: "test", Sequence: seq, Data: make([]byte, 100)}
		buf.buffer[seq] = &txPayload{payload: payload, x: x, age: time.Now().UnixMilli()}

		rttStamp := uint16(time.Now().UnixMilli()) - uint16(50)
		ack := &Acknowledgement{
			CircuitId:      "test",
			Sequence:       []int32{seq},
			RTT:            rttStamp,
			RecvBufferSize: 1024 * 1024,
		}
		buf.receiveAcknowledgement(ack)
	}

	baseline := buf.lastRtt

	// Inject a spike
	seq := int32(10)
	payload := &Payload{CircuitId: "test", Sequence: seq, Data: make([]byte, 100)}
	buf.buffer[seq] = &txPayload{payload: payload, x: x, age: time.Now().UnixMilli()}
	rttStamp := uint16(time.Now().UnixMilli()) - uint16(53000)
	ack := &Acknowledgement{
		CircuitId:      "test",
		Sequence:       []int32{seq},
		RTT:            rttStamp,
		RecvBufferSize: 1024 * 1024,
	}
	buf.receiveAcknowledgement(ack)

	// Feed stable samples and verify recovery
	for i := 11; i < 21; i++ {
		seq := int32(i)
		payload := &Payload{CircuitId: "test", Sequence: seq, Data: make([]byte, 100)}
		buf.buffer[seq] = &txPayload{payload: payload, x: x, age: time.Now().UnixMilli()}

		rttStamp := uint16(time.Now().UnixMilli()) - uint16(50)
		ack := &Acknowledgement{
			CircuitId:      "test",
			Sequence:       []int32{seq},
			RTT:            rttStamp,
			RecvBufferSize: 1024 * 1024,
		}
		buf.receiveAcknowledgement(ack)
	}

	t.Logf("after recovery: lastRtt=%d (baseline=%d), retxThreshold=%d",
		buf.lastRtt, baseline, buf.retxThreshold)

	// With the 2-sample average, recovery is fast — should be close to baseline
	// after 10 stable samples
	req.InDelta(float64(baseline), float64(buf.lastRtt), 20,
		"lastRtt should recover close to baseline after 10 stable samples")
}

func TestRttHardCap(t *testing.T) {
	req := require.New(t)
	opts := DefaultOptions()
	opts.RetxMaxMs = 5000

	conn := &testConn{closeNotify: make(chan struct{})}
	x := NewXgress("test", "ctrl", "test", conn, Initiator, opts, nil)
	x.dataPlane = noopReceiveHandler{payloadIngester: NewPayloadIngester(make(chan struct{}))}
	buf := NewLinkSendBuffer(x)

	// Feed high RTT samples to push threshold up
	for i := 0; i < 10; i++ {
		seq := int32(i)
		payload := &Payload{CircuitId: "test", Sequence: seq, Data: make([]byte, 100)}
		buf.buffer[seq] = &txPayload{payload: payload, x: x, age: time.Now().UnixMilli()}

		rttStamp := uint16(time.Now().UnixMilli()) - uint16(2000)
		ack := &Acknowledgement{
			CircuitId:      "test",
			Sequence:       []int32{seq},
			RTT:            rttStamp,
			RecvBufferSize: 1024 * 1024,
		}
		buf.receiveAcknowledgement(ack)
	}

	t.Logf("high RTT: lastRtt=%d, retxThreshold=%d", buf.lastRtt, buf.retxThreshold)

	req.LessOrEqual(buf.retxThreshold, opts.RetxMaxMs,
		"retxThreshold must never exceed RetxMaxMs")
}
