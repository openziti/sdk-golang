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
	"encoding/binary"
	"fmt"
	"math"
	"sync/atomic"

	"github.com/openziti/channel/v5"
	"github.com/openziti/foundation/v2/info"
	"github.com/openziti/foundation/v2/uuidz"
	"github.com/openziti/sdk-golang/v2/pb/edge_client_pb"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	MinHeaderKey = 2000
	MaxHeaderKey = MinHeaderKey + int32(math.MaxUint8)

	HeaderKeyCircuitId      = int32(edge_client_pb.HeaderId_XgCircuitId)
	HeaderKeySequence       = int32(edge_client_pb.HeaderId_XgSequence)
	HeaderKeyFlags          = int32(edge_client_pb.HeaderId_XgFlags)
	HeaderKeyRecvBufferSize = int32(edge_client_pb.HeaderId_XgRecvBufferSize)
	HeaderKeyRTT            = int32(edge_client_pb.HeaderId_XgRTT)
	HeaderPayloadRaw        = int32(edge_client_pb.HeaderId_XgPayloadRaw)

	ContentTypePayloadType         = int32(edge_client_pb.ContentType_XgPayloadType)
	ContentTypeAcknowledgementType = int32(edge_client_pb.ContentType_XgAcknowledgementType)
	ContentTypeControlType         = int32(edge_client_pb.ContentType_XgControlType)
)

var ContentTypeValue = map[string]int32{
	"PayloadType":         ContentTypePayloadType,
	"AcknowledgementType": ContentTypeAcknowledgementType,
	"ControlType":         ContentTypeControlType,
}

type Originator int32

const (
	Initiator  Originator = 0
	Terminator Originator = 1
)

func (o Originator) String() string {
	if o == Initiator {
		return "Initiator"
	}
	return "Terminator"
}

func (o Originator) Invert() Originator {
	if o == Initiator {
		return Terminator
	}
	return Initiator
}

type Flag uint32

const (
	PayloadFlagCircuitEnd   = Flag(edge_client_pb.XgPayloadFlag_CircuitEnd)
	PayloadFlagOriginator   = Flag(edge_client_pb.XgPayloadFlag_Originator)
	PayloadFlagCircuitStart = Flag(edge_client_pb.XgPayloadFlag_CircuitStart)
	PayloadFlagChunk        = Flag(edge_client_pb.XgPayloadFlag_Chunk)
	PayloadFlagRetransmit   = Flag(edge_client_pb.XgPayloadFlag_Retransmit)
	PayloadFlagEOF          = Flag(edge_client_pb.XgPayloadFlag_EOF)
	PayloadFlagWriteFailed  = Flag(edge_client_pb.XgPayloadFlag_WriteFailed)
)

const (
	HeaderKeyUUID         = uint8(edge_client_pb.XgHeaderKey_UUID)
	HeaderKeyCapabilities = uint8(edge_client_pb.XgHeaderKey_Capabilities)
)

func NewAcknowledgement(circuitId string, originator Originator) *Acknowledgement {
	return &Acknowledgement{
		CircuitId: circuitId,
		Flags:     SetOriginatorFlag(0, originator),
	}
}

type Acknowledgement struct {
	CircuitId      string
	Flags          uint32
	RecvBufferSize uint32
	RTT            uint16
	Sequence       []int32
}

func (ack *Acknowledgement) GetCircuitId() string {
	return ack.CircuitId
}

func (ack *Acknowledgement) GetFlags() uint32 {
	return ack.Flags
}

func (ack *Acknowledgement) GetOriginator() Originator {
	if isFlagSet(ack.Flags, PayloadFlagOriginator) {
		return Terminator
	}
	return Initiator
}

func (ack *Acknowledgement) GetSequence() []int32 {
	return ack.Sequence
}

func (ack *Acknowledgement) marshallSequence() []byte {
	if len(ack.Sequence) == 0 {
		return nil
	}
	buf := make([]byte, len(ack.Sequence)*4)
	nextWriteBuf := buf
	for _, seq := range ack.Sequence {
		binary.BigEndian.PutUint32(nextWriteBuf, uint32(seq))
		nextWriteBuf = nextWriteBuf[4:]
	}
	return buf
}

func (ack *Acknowledgement) unmarshallSequence(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	if len(data)%4 != 0 {
		return fmt.Errorf("received sequence with wrong number of bytes: %v", len(data))
	}
	ack.Sequence = make([]int32, len(data)/4)

	nextReadBuf := data
	for i := range ack.Sequence {
		ack.Sequence[i] = int32(binary.BigEndian.Uint32(nextReadBuf))
		nextReadBuf = nextReadBuf[4:]
	}
	return nil
}

func (ack *Acknowledgement) Marshall() *channel.Message {
	msg := channel.NewMessage(ContentTypeAcknowledgementType, ack.marshallSequence())
	msg.PutUint16Header(HeaderKeyRTT, ack.RTT)
	msg.Headers[HeaderKeyCircuitId] = []byte(ack.CircuitId)
	if ack.Flags != 0 {
		msg.PutUint32Header(HeaderKeyFlags, ack.Flags)
	}
	msg.PutUint32Header(HeaderKeyRecvBufferSize, ack.RecvBufferSize)
	return msg
}

func UnmarshallAcknowledgement(msg *channel.Message) (*Acknowledgement, error) {
	ack := &Acknowledgement{}

	circuitId, ok := msg.Headers[HeaderKeyCircuitId]
	if !ok {
		return nil, fmt.Errorf("no circuitId found in xgress payload message")
	}

	// If no flags are present, it just means no flags have been set
	flags, _ := msg.GetUint32Header(HeaderKeyFlags)

	ack.CircuitId = string(circuitId)
	ack.Flags = flags
	if ack.RecvBufferSize, ok = msg.GetUint32Header(HeaderKeyRecvBufferSize); !ok {
		ack.RecvBufferSize = math.MaxUint32
	}

	ack.RTT, _ = msg.GetUint16Header(HeaderKeyRTT)

	if err := ack.unmarshallSequence(msg.Body); err != nil {
		return nil, err
	}

	return ack, nil
}

func (ack *Acknowledgement) GetLoggerFields() logrus.Fields {
	return logrus.Fields{
		"circuitId":          ack.CircuitId,
		"linkRecvBufferSize": ack.RecvBufferSize,
		"seq":                fmt.Sprintf("%+v", ack.Sequence),
		"RTT":                ack.RTT,
	}
}

// PayloadType classifies how a payload is handed to a link. It is a local hint only, used to pick
// which dropped-message meter to mark, and is never serialized, so it is not part of the proto.
type PayloadType byte

const (
	// PayloadTypeXg is an ordinary payload, sent with a timeout
	PayloadTypeXg PayloadType = 1
	// PayloadTypeRtx is a retransmission, which does not mark the circuit active
	PayloadTypeRtx PayloadType = 2
	// PayloadTypeFwd is a payload forwarded without blocking (zero timeout)
	PayloadTypeFwd PayloadType = 3
)

type Payload struct {
	CircuitId string
	Flags     uint32
	RTT       uint16
	Sequence  int32
	Headers   map[uint8][]byte
	Data      []byte
	raw       []byte
}

func (payload *Payload) GetSequence() int32 {
	return payload.Sequence
}

func (payload *Payload) Marshall() *channel.Message {
	if payload.raw != nil {
		if payload.raw[0]&RttFlagMask != 0 {
			rtt := uint16(info.NowInMilliseconds())
			b0 := byte(rtt)
			b1 := byte(rtt >> 8)
			payload.raw[2] = b0
			payload.raw[3] = b1
		}
		return channel.NewMessage(channel.ContentTypeRaw, payload.raw)
	}

	msg := channel.NewMessage(ContentTypePayloadType, payload.Data)
	addPayloadHeadersToMsg(msg, payload.Headers)
	msg.Headers[HeaderKeyCircuitId] = []byte(payload.CircuitId)
	if flags := payload.GetFlags(); flags != 0 {
		msg.PutUint32Header(HeaderKeyFlags, flags)
	}

	msg.PutUint64Header(HeaderKeySequence, uint64(payload.Sequence))
	msg.PutUint16Header(HeaderKeyRTT, uint16(info.NowInMilliseconds()))

	return msg
}

func addPayloadHeadersToMsg(msg *channel.Message, headers map[uint8][]byte) {
	for key, value := range headers {
		msgHeaderKey := MinHeaderKey + int32(key)
		msg.Headers[msgHeaderKey] = value
	}
}

func UnmarshallPayload(msg *channel.Message) (*Payload, error) {
	var headers map[uint8][]byte
	for key, val := range msg.Headers {
		if key >= MinHeaderKey && key <= MaxHeaderKey {
			if headers == nil {
				headers = make(map[uint8][]byte)
			}
			xgressHeaderKey := uint8(key - MinHeaderKey)
			headers[xgressHeaderKey] = val
		}
	}

	payload := &Payload{
		Headers: headers,
		Data:    msg.Body,
	}

	circuitId, ok := msg.Headers[HeaderKeyCircuitId]
	if !ok {
		return nil, fmt.Errorf("no circuitId found in xgress payload message")
	}

	// If no flags are present, it just means no flags have been set
	flags, _ := msg.GetUint32Header(HeaderKeyFlags)

	payload.CircuitId = string(circuitId)
	payload.Flags = flags

	payload.RTT, _ = msg.GetUint16Header(HeaderKeyRTT)

	sequence, ok := msg.GetUint64Header(HeaderKeySequence)
	if !ok {
		return nil, fmt.Errorf("no sequence found in xgress payload message")
	}
	payload.Sequence = int32(sequence)

	if raw, ok := msg.Headers[HeaderPayloadRaw]; ok {
		payload.raw = raw
	}

	return payload, nil
}

func isFlagSet(flags uint32, flag Flag) bool {
	return Flag(flags)&flag == flag
}

func setPayloadFlag(flags uint32, flag Flag) uint32 {
	return uint32(Flag(flags) | flag)
}

func (payload *Payload) GetCircuitId() string {
	return payload.CircuitId
}

// GetFlags returns the payload's flags using an atomic load, safe for concurrent access.
func (payload *Payload) GetFlags() uint32 {
	return atomic.LoadUint32(&payload.Flags)
}

func (payload *Payload) IsCircuitEndFlagSet() bool {
	return isFlagSet(payload.GetFlags(), PayloadFlagCircuitEnd)
}

func (payload *Payload) IsFlagEOFSet() bool {
	return isFlagSet(payload.GetFlags(), PayloadFlagEOF)
}

func (payload *Payload) IsFlagWriteFailedSet() bool {
	return isFlagSet(payload.GetFlags(), PayloadFlagWriteFailed)
}

func (payload *Payload) IsCircuitStartFlagSet() bool {
	return isFlagSet(payload.GetFlags(), PayloadFlagCircuitStart)
}

func (payload *Payload) IsRetransmitFlagSet() bool {
	return isFlagSet(payload.GetFlags(), PayloadFlagRetransmit)
}

// MarkAsRetransmit atomically sets the retransmit flag. Safe for concurrent use.
func (payload *Payload) MarkAsRetransmit() {
	atomic.OrUint32(&payload.Flags, uint32(PayloadFlagRetransmit))
}

func (payload *Payload) GetOriginator() Originator {
	if isFlagSet(payload.GetFlags(), PayloadFlagOriginator) {
		return Terminator
	}
	return Initiator
}

func SetOriginatorFlag(flags uint32, originator Originator) uint32 {
	if originator == Initiator {
		return ^uint32(PayloadFlagOriginator) & flags
	}
	return uint32(PayloadFlagOriginator) | flags
}

func (payload *Payload) GetLoggerFields() logrus.Fields {
	result := logrus.Fields{
		"circuitId": payload.CircuitId,
		"seq":       payload.Sequence,
		"origin":    payload.GetOriginator(),
	}

	if uuidVal, found := payload.Headers[HeaderKeyUUID]; found {
		result["uuid"] = uuidz.ToString(uuidVal)
	}

	return result
}

type ControlType byte

func (self ControlType) String() string {
	switch self {
	case ControlTypeTraceRoute:
		return "traceroute"
	case ControlTypeTraceRouteResponse:
		return "traceroute_response"
	default:
		return fmt.Sprintf("unhandled: %v", byte(self))
	}
}

const (
	ControlTypeTraceRoute         = ControlType(edge_client_pb.XgControl_TraceRoute)
	ControlTypeTraceRouteResponse = ControlType(edge_client_pb.XgControl_TraceRouteResponse)
)

const (
	ControlHopCount  = int32(edge_client_pb.XgControlHeader_HopCount)
	ControlHopType   = int32(edge_client_pb.XgControlHeader_HopType)
	ControlHopId     = int32(edge_client_pb.XgControlHeader_HopId)
	ControlTimestamp = int32(edge_client_pb.XgControlHeader_Timestamp)
	ControlUserVal   = int32(edge_client_pb.XgControlHeader_UserVal)
	ControlError     = int32(edge_client_pb.XgControlHeader_Error)
)

type Control struct {
	Type      ControlType
	CircuitId string
	Headers   channel.Headers
}

func (self *Control) Marshall() *channel.Message {
	msg := channel.NewMessage(ContentTypeControlType, append([]byte{byte(self.Type)}, self.CircuitId...))
	msg.Headers = self.Headers
	return msg
}

func UnmarshallControl(msg *channel.Message) (*Control, error) {
	if len(msg.Body) < 2 {
		return nil, errors.New("control message body too short")
	}
	return &Control{
		Type:      ControlType(msg.Body[0]),
		CircuitId: string(msg.Body[1:]),
		Headers:   msg.Headers,
	}, nil
}

func (self *Control) IsTypeTraceRoute() bool {
	return self.Type == ControlTypeTraceRoute
}

func (self *Control) IsTypeTraceRouteResponse() bool {
	return self.Type == ControlTypeTraceRouteResponse
}

func (self *Control) DecrementAndGetHop() uint32 {
	hop, _ := self.Headers.GetUint32Header(ControlHopCount)
	if hop == 0 {
		return 0
	}
	hop--
	self.Headers.PutUint32Header(ControlHopCount, hop)
	return hop
}

func (self *Control) CreateTraceResponse(hopType, hopId string) *Control {
	resp := &Control{
		Type:      ControlTypeTraceRouteResponse,
		CircuitId: self.CircuitId,
		Headers:   self.Headers,
	}
	resp.Headers.PutStringHeader(ControlHopType, hopType)
	resp.Headers.PutStringHeader(ControlHopId, hopId)
	return resp
}

func (self *Control) GetLoggerFields() logrus.Fields {
	result := logrus.Fields{
		"circuitId": self.CircuitId,
		"type":      self.Type,
	}

	if uuidVal, found := self.Headers[int32(HeaderKeyUUID)]; found {
		result["uuid"] = uuidz.ToString(uuidVal)
	}

	return result
}

func RespondToTraceRequest(headers channel.Headers, hopType, hopId string, response ControlReceiver) {
	resp := &Control{Headers: headers}
	resp.DecrementAndGetHop()
	resp.Headers.PutStringHeader(ControlHopType, hopType)
	resp.Headers.PutStringHeader(ControlHopId, hopId)
	response.HandleControlReceive(ControlTypeTraceRouteResponse, headers)
}

type InvalidTerminatorError struct {
	InnerError error
}

func (e InvalidTerminatorError) Error() string {
	return e.InnerError.Error()
}

func (e InvalidTerminatorError) Unwrap() error {
	return e.InnerError
}

type MisconfiguredTerminatorError struct {
	InnerError error
}

func (e MisconfiguredTerminatorError) Error() string {
	return e.InnerError.Error()
}

func (e MisconfiguredTerminatorError) Unwrap() error {
	return e.InnerError
}
