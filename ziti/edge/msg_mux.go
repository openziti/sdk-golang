/*
	Copyright 2019 NetFoundry Inc.

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
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/inspect"
	"github.com/openziti/sdk-golang/xgress"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"math"
	"strings"
	"sync/atomic"
	"time"
)

type MsgSink interface {
	HandleMuxClose() error
	Id() uint32
	Accept(msg *channel.Message)
}

type MsgMux interface {
	channel.TypedReceiveHandler
	channel.CloseHandler
	AddMsgSink(sink MsgSink) error
	RemoveMsgSink(sink MsgSink)
	RemoveMsgSinkById(sinkId uint32)
	Close()
	GetNextId() uint32
}

func NewMapMsgMux() MsgMux {
	result := &MsgMuxImpl{
		maxId: (math.MaxUint32 / 2) - 1,
		sinks: cmap.NewWithCustomShardingFunction[uint32, MsgSink](func(key uint32) uint32 {
			return key
		}),
	}
	return result
}

type MsgMuxImpl struct {
	closed atomic.Bool
	sinks  cmap.ConcurrentMap[uint32, MsgSink]
	nextId uint32
	minId  uint32
	maxId  uint32
}

func (mux *MsgMuxImpl) GetNextId() uint32 {
	nextId := atomic.AddUint32(&mux.nextId, 1)
	for {
		if _, found := mux.sinks.Get(nextId); found {
			// if it's in use, try next one
			nextId = atomic.AddUint32(&mux.nextId, 1)
		} else if nextId < mux.minId || nextId >= mux.maxId {
			// it's not in use, but not in the valid range, so reset to beginning of range
			atomic.StoreUint32(&mux.nextId, mux.minId)
			nextId = atomic.AddUint32(&mux.nextId, 1)
		} else {
			// If it's not in use, and in the valid range, return it
			return nextId
		}
	}
}

func (mux *MsgMuxImpl) ContentType() int32 {
	return ContentTypeData
}

func (mux *MsgMuxImpl) HandleReceive(msg *channel.Message, ch channel.Channel) {
	connId, found := msg.GetUint32Header(ConnIdHeader)
	if !found {
		if msg.ContentType == ContentTypeInspectRequest {
			mux.HandleInspect(msg, ch)
			return
		}
		pfxlog.Logger().Errorf("received edge message with no connId header. content type: %v", msg.ContentType)
		return
	}

	if sink, found := mux.sinks.Get(connId); found {
		sink.Accept(msg)
	} else if msg.ContentType == ContentTypeConnInspectRequest {
		pfxlog.Logger().WithField("connId", int(connId)).Trace("no conn found for connection inspect")
		resp := NewConnInspectResponse(connId, ConnTypeInvalid, fmt.Sprintf("invalid conn id [%v]", connId))
		if err := resp.ReplyTo(msg).Send(ch); err != nil {
			logrus.WithFields(GetLoggerFields(msg)).WithError(err).
				Error("failed to send inspect response")
		}
	} else if msg.ContentType == ContentTypeXgPayload {
		mux.handlePayloadWithNoSink(msg, ch)
	} else if msg.ContentType == ContentTypeStateClosed {
		// ignore, as conn is already closed
	} else {
		pfxlog.Logger().WithField("connId", connId).WithField("contentType", msg.ContentType).
			Debug("unable to dispatch msg received for unknown edge conn id")
	}
}

func (mux *MsgMuxImpl) handlePayloadWithNoSink(msg *channel.Message, ch channel.Channel) {
	connId, _ := msg.GetUint32Header(ConnIdHeader)
	payload, err := xgress.UnmarshallPayload(msg)
	if err == nil {
		if (payload.IsCircuitEndFlagSet() || payload.IsFlagEOFSet()) && len(payload.Data) == 0 {
			ack := xgress.NewAcknowledgement(payload.CircuitId, payload.GetOriginator().Invert())
			ackMsg := ack.Marshall()
			ackMsg.PutUint32Header(ConnIdHeader, connId)
			_, _ = ch.TrySend(msg)
		} else {
			pfxlog.Logger().WithField("connId", int(connId)).WithField("circuitId", payload.CircuitId).
				Debug("unable to dispatch xg payload received for unknown edge conn id")
		}
	} else {
		pfxlog.Logger().WithError(err).WithField("connId", int(connId)).
			Debug("unable to dispatch xg payload received for unknown edge conn id")
	}
}

func (mux *MsgMuxImpl) HandleInspect(msg *channel.Message, ch channel.Channel) {
	resp := &inspect.SdkInspectResponse{
		Success: true,
		Values:  make(map[string]any),
	}
	requestedValues, _, err := msg.GetStringSliceHeader(InspectRequestValuesHeader)
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
		resp.Success = false
		mux.returnInspectResponse(msg, ch, resp)
		return
	}

	for _, requested := range requestedValues {
		lc := strings.ToLower(requested)
		if lc == "circuits" {
			circuitsDetail := &xgress.CircuitsDetail{
				Circuits: make(map[string]*xgress.CircuitDetail),
			}

			for _, sink := range mux.sinks.Items() {
				if circuitInfoSrc, ok := sink.(interface {
					GetCircuitDetail() *xgress.CircuitDetail
				}); ok {
					circuitDetail := circuitInfoSrc.GetCircuitDetail()
					if circuitDetail != nil {
						circuitsDetail.Circuits[circuitDetail.CircuitId] = circuitDetail
					}
				}
			}
			resp.Values[requested] = circuitsDetail
		}
	}

	mux.returnInspectResponse(msg, ch, resp)
}

func (mux *MsgMuxImpl) returnInspectResponse(msg *channel.Message, ch channel.Channel, resp *inspect.SdkInspectResponse) {
	var sender channel.Sender = ch
	if mc, ok := ch.(channel.MultiChannel); ok {
		if sdkChan, ok := mc.GetUnderlayHandler().(SdkChannel); ok {
			sender = sdkChan.GetControlSender()
		}
	}

	reply, err := NewInspectResponse(0, resp)
	if err != nil {
		pfxlog.Logger().WithError(err).Error("failed to create inspect response")
		return
	}
	reply.ReplyTo(msg)

	if err = reply.WithTimeout(5 * time.Second).Send(sender); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send inspect response")
	}
}

func (mux *MsgMuxImpl) HandleClose(channel.Channel) {
	mux.Close()
}

func (mux *MsgMuxImpl) AddMsgSink(sink MsgSink) error {
	if mux.closed.Load() {
		return errors.Errorf("mux is closed, can't add sink with id [%v]", sink.Id())
	}

	if !mux.sinks.SetIfAbsent(sink.Id(), sink) {
		return errors.Errorf("sink id %v already in use", sink.Id())
	}
	return nil
}

func (mux *MsgMuxImpl) RemoveMsgSink(sink MsgSink) {
	mux.RemoveMsgSinkById(sink.Id())
}

func (mux *MsgMuxImpl) RemoveMsgSinkById(sinkId uint32) {
	mux.sinks.Remove(sinkId)
}

func (mux *MsgMuxImpl) Close() {
	if mux.closed.CompareAndSwap(false, true) {
		// we don't need to lock the mux because due to the atomic bool, only one go-routine will enter this.
		// If the sink HandleMuxClose methods do anything with the mux, like remove themselves, they will acquire
		// their own locks
		sinks := mux.sinks.Items()
		for _, val := range sinks {
			if err := val.HandleMuxClose(); err != nil {
				pfxlog.Logger().
					WithField("sinkId", val.Id()).
					WithError(err).
					Error("error while closing message sink")
			}
		}
	}
}
