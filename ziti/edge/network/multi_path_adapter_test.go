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

package network

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/stretchr/testify/require"
)

// countingSender is a concurrency-safe RouterSender that counts sends.
type countingSender struct {
	payloads atomic.Int64
	acks     atomic.Int64
	controls atomic.Int64
	closed   atomic.Bool
}

func (s *countingSender) SendPayload(*channel.Message, context.Context) error {
	s.payloads.Add(1)
	return nil
}

func (s *countingSender) TrySendPayload(*channel.Message) (bool, error) {
	s.payloads.Add(1)
	return true, nil
}

func (s *countingSender) SendAcknowledgement(*channel.Message) error {
	s.acks.Add(1)
	return nil
}

func (s *countingSender) SendControlMessage(*channel.Message) error {
	s.controls.Add(1)
	return nil
}

func (s *countingSender) IsClosed() bool {
	return s.closed.Load()
}

func newTestPath(routerId string, connId uint32) (*RouterChannelPath, *countingSender) {
	sender := &countingSender{}
	return &RouterChannelPath{sender: sender, connId: connId, routerId: routerId}, sender
}

// testEnv is a configurable Env for tests. The adapter tests use the zero
// value, since they never exercise the ingester or metrics passthroughs; the
// receive-path tests supply a live ingester and noop metrics.
type testEnv struct {
	ingester *xgress.PayloadIngester
	metrics  xgress.Metrics
}

func (e testEnv) GetPayloadIngester() *xgress.PayloadIngester { return e.ingester }
func (e testEnv) GetMetrics() xgress.Metrics                  { return e.metrics }

func newTestEnv() xgress.Env {
	return testEnv{}
}

func TestSinglePathSelector(t *testing.T) {
	req := require.New(t)

	pathA, _ := newTestPath("a", 1)
	pathB, _ := newTestPath("b", 2)
	selector := SinglePathSelector{}

	payload := &xgress.Payload{CircuitId: "c1"}
	req.Nil(selector.SelectForPayload(nil, payload))
	req.Nil(selector.SelectForRetransmit(nil, payload, nil))
	req.Nil(selector.Primary(nil))

	paths := []Path{pathA, pathB}
	req.Equal(Path(pathA), selector.SelectForPayload(paths, payload))
	req.Equal(Path(pathA), selector.SelectForRetransmit(paths, payload, pathB))
	req.Equal(Path(pathA), selector.Primary(paths))
}

func TestMultiPathAdapterForwarding(t *testing.T) {
	req := require.New(t)

	pathA, senderA := newTestPath("a", 1)
	pathB, senderB := newTestPath("b", 2)
	adapter := NewMultiPathAdapter("c1", newTestEnv(), SinglePathSelector{}, pathA)

	payload := &xgress.Payload{CircuitId: "c1", Sequence: 1}

	// payloads dispatch to the selected path and return it as the tag
	tag := adapter.ForwardPayload(payload, nil, context.Background())
	req.Equal(xgress.Path(pathA), tag)
	req.EqualValues(1, senderA.payloads.Load())

	// retransmits return the new carrying path as the tag
	newTag, err := adapter.RetransmitPayload(tag, "addr", payload)
	req.NoError(err)
	req.Equal(xgress.Path(pathA), newTag)
	req.EqualValues(2, senderA.payloads.Load())

	// with no arrival path, acks go to the primary
	ack := xgress.NewAcknowledgement("c1", xgress.Initiator)
	adapter.ForwardAcknowledgement(ack, "addr", nil)
	req.EqualValues(1, senderA.acks.Load())

	// with a live, attached arrival path, acks follow arrival affinity
	adapter.AddPath(pathB)
	adapter.ForwardAcknowledgement(ack, "addr", pathB)
	req.EqualValues(1, senderB.acks.Load())
	req.EqualValues(1, senderA.acks.Load())

	// a detached arrival path falls back to the primary
	adapter.RemovePath(pathB)
	adapter.ForwardAcknowledgement(ack, "addr", pathB)
	req.EqualValues(1, senderB.acks.Load())
	req.EqualValues(2, senderA.acks.Load())

	// a closed arrival path falls back to the primary
	adapter.AddPath(pathB)
	senderB.closed.Store(true)
	adapter.ForwardAcknowledgement(ack, "addr", pathB)
	req.EqualValues(1, senderB.acks.Load())
	req.EqualValues(3, senderA.acks.Load())
}

func TestMultiPathAdapterNoPath(t *testing.T) {
	req := require.New(t)

	pathA, _ := newTestPath("a", 1)
	adapter := NewMultiPathAdapter("c1", newTestEnv(), SinglePathSelector{}, pathA)
	adapter.RemovePath(pathA)

	payload := &xgress.Payload{CircuitId: "c1", Sequence: 1}

	// the no-send contract: nil tag, payload not handed to any transport
	req.Nil(adapter.ForwardPayload(payload, nil, context.Background()))

	tag, err := adapter.RetransmitPayload(nil, "addr", payload)
	req.NoError(err)
	req.Nil(tag)
}

func TestMultiPathAdapterConcurrentAddRemove(t *testing.T) {
	req := require.New(t)

	pathA, senderA := newTestPath("a", 1)
	pathB, senderB := newTestPath("b", 2)
	adapter := NewMultiPathAdapter("c1", newTestEnv(), SinglePathSelector{}, pathA)

	var done atomic.Bool
	var sent atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seq := int32(0)
			for !done.Load() {
				seq++
				payload := &xgress.Payload{CircuitId: "c1", Sequence: seq}
				if tag := adapter.ForwardPayload(payload, nil, context.Background()); tag != nil {
					req.True(tag == xgress.Path(pathA) || tag == xgress.Path(pathB))
					sent.Add(1)
				}
				adapter.ForwardAcknowledgement(xgress.NewAcknowledgement("c1", xgress.Initiator), "addr", nil)
			}
		}()
	}

	for i := 0; i < 1000; i++ {
		adapter.AddPath(pathB)
		adapter.RemovePath(pathA)
		adapter.AddPath(pathA)
		adapter.RemovePath(pathB)
	}
	done.Store(true)
	wg.Wait()

	req.Len(adapter.Paths(), 1)
	req.Equal(sent.Load(), senderA.payloads.Load()+senderB.payloads.Load())
}
