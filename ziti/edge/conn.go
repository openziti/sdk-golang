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
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/foundation/v2/concurrenz"
	"github.com/openziti/foundation/v2/sequence"
	"github.com/openziti/sdk-golang/inspect"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/secretstream/kx"
)

const (
	ConnFlagIdxFirstMsgSent = 0
)

func init() {
	AddAddressParsers()
}

type RouterClient interface {
	Connect(ctx context.Context, service *rest_model.ServiceDetail, session *rest_model.SessionDetail, options *DialOptions, envF func() xgress.Env) (Conn, error)
	Listen(options *ListenOptions) (RouterHostConn, error)

	//UpdateToken will attempt to send token updates to the connected router. A success/failure response is expected
	//within the timeout period.
	UpdateToken(token []byte, timeout time.Duration) error

	SendPosture(creates []rest_model.PostureResponseCreate) error
}

// EdgeRouterInfo contains the name and address of an edge router.
type EdgeRouterInfo struct {
	Name string
	Addr string
}

// RouterHostConn represents a hosting-side connection to an edge router.
type RouterHostConn interface {
	Identifiable
	// GetEdgeRouterInfo returns the name and address of the edge router for this connection.
	GetEdgeRouterInfo() EdgeRouterInfo
}

// ListenerHost is the parent-facing surface that per-router child listeners
// (edgeHostConn instances) call back into. A multi-listener implements this
// directly; the listener manager wraps it with per-attempt context (router
// name, attempt id) so that the wrapper handles close notification while
// QueueDial and AcceptConn delegate straight to the multi-listener.
type ListenerHost interface {
	// QueueDial submits dial-handling work to the listener's bounded worker
	// pool. Returns a non-nil error when the pool is saturated or shut down;
	// the caller is responsible for replying DialFailed to the router.
	QueueDial(work func()) error
	// AcceptConn delivers an established Conn to the application accept queue.
	// Returns false when the listener has been closed and the conn could not
	// be delivered; the caller should close the conn since the application
	// will not consume it.
	AcceptConn(c Conn) bool
	// NotifyRouterConnClosed is invoked exactly once when a child listener
	// closes. Implementations typically remove the child from the listener
	// set and, if applicable, queue a re-listen attempt for the same router.
	NotifyRouterConnClosed(child RouterHostConn)
}

type RouterConn interface {
	channel.BindHandler
	io.Closer
	RouterClient
	IsClosed() bool
	// GetRouterAddr returns the address used to connect to the edge router.
	GetRouterAddr() string
	GetRouterName() string
	GetBoolHeader(key int32) bool
	Inspect() *inspect.RouterConnInspectDetail
}

type Identifiable interface {
	Id() uint32
}

type Listener interface {
	net.Listener
	Identifiable
	AcceptEdge() (Conn, error)
	IsClosed() bool
	UpdateCost(cost uint16) error
	UpdatePrecedence(precedence Precedence) error
	UpdateCostAndPrecedence(cost uint16, precedence Precedence) error
	SendHealthEvent(pass bool) error
}

type SessionListener interface {
	Listener
	GetCurrentSession() *rest_model.SessionDetail
	SetConnectionChangeHandler(func(conn []RouterHostConn))
	SetErrorEventHandler(func(error))
	GetErrorEventHandler() func(error)
}

type CloseWriter interface {
	CloseWrite() error
}

type ServiceConn interface {
	net.Conn
	CloseWriter
	IsClosed() bool
	GetAppData() []byte
	SourceIdentifier() string
	TraceRoute(hops uint32, timeout time.Duration) (*TraceRouteResult, error)
	GetCircuitId() string
	GetStickinessToken() []byte
	GetDialerIdentityId() string
	GetDialerIdentityName() string
}

type Conn interface {
	ServiceConn
	Identifiable
	GetRouterId() string
	GetState() string
	CompleteAcceptSuccess() error
	CompleteAcceptFailed(err error)
}

const forever = time.Hour * 24 * 365 * 100

type MsgChannel struct {
	SdkChannel
	id            uint32
	msgIdSeq      *sequence.Sequence
	writeDeadline time.Time
	trace         bool
	flags         concurrenz.AtomicBitSet
}

type TraceRouteResult struct {
	Hops    uint32
	Time    time.Duration
	HopType string
	HopId   string
	Error   string
}

func NewEdgeMsgChannel(ch SdkChannel, connId uint32) *MsgChannel {
	traceEnabled := strings.EqualFold("true", os.Getenv("ZITI_TRACE_ENABLED"))
	if traceEnabled {
		pfxlog.Logger().Info("Ziti message tracing ENABLED")
	}

	return &MsgChannel{
		SdkChannel: ch,
		id:         connId,
		msgIdSeq:   sequence.NewSequence(),
		trace:      traceEnabled,
	}
}

func (ec *MsgChannel) GetRouterId() string {
	return ec.GetChannel().Id()
}

func (ec *MsgChannel) Id() uint32 {
	return ec.id
}

func (ec *MsgChannel) NextMsgId() uint32 {
	return ec.msgIdSeq.Next()
}

func (ec *MsgChannel) SetWriteDeadline(t time.Time) error {
	ec.writeDeadline = t
	return nil
}

func (ec *MsgChannel) Write(data []byte) (n int, err error) {
	return ec.WriteTraced(data, nil, nil)
}

func (ec *MsgChannel) WriteTraced(data []byte, msgUUID []byte, hdrs map[int32][]byte) (int, error) {
	msg := NewDataMsg(ec.id, data)
	if msgUUID != nil {
		msg.Headers[UUIDHeader] = msgUUID
	}

	for k, v := range hdrs {
		msg.Headers[k] = v
	}

	// indicate that we can accept multipart messages
	// with the first message
	if ec.flags.CompareAndSet(ConnFlagIdxFirstMsgSent, false, true) {
		flags, _ := msg.GetUint32Header(FlagsHeader)
		flags = flags | MULTIPART
		msg.PutUint32Header(FlagsHeader, flags)
	}
	ec.TraceMsg("write", msg)
	pfxlog.Logger().WithFields(GetLoggerFields(msg)).Debugf("writing %v bytes", len(data))

	// NOTE: We need to wait for the buffer to be on the wire before returning. The Writer contract
	//       states that buffers are not allowed be retained, and if we have it queued asynchronously
	//       it is retained, and we can cause data corruption
	var err error
	if ec.writeDeadline.IsZero() {
		err = msg.WithTimeout(forever).SendAndWaitForWire(ec.GetDefaultSender())
	} else {
		err = msg.WithTimeout(time.Until(ec.writeDeadline)).SendAndWaitForWire(ec.GetDefaultSender())
	}

	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (ec *MsgChannel) SendState(msg *channel.Message) error {
	msg.PutUint32Header(SeqHeader, ec.msgIdSeq.Next())
	ec.TraceMsg("SendState", msg)
	return msg.WithTimeout(5 * time.Second).SendAndWaitForWire(ec.GetDefaultSender())
}

func (ec *MsgChannel) TraceMsg(source string, msg *channel.Message) {
	msgUUID, found := msg.Headers[UUIDHeader]
	if ec.trace && !found {
		newUUID, err := uuid.NewRandom()
		if err == nil {
			msgUUID = newUUID[:]
			msg.Headers[UUIDHeader] = msgUUID
		} else {
			pfxlog.Logger().WithField("connId", ec.id).WithError(err).Infof("failed to create trace uuid")
		}
	}

	if msgUUID != nil {
		pfxlog.Logger().WithFields(GetLoggerFields(msg)).WithField("source", source).Debug("tracing message")
	}
}

type ConnOptions interface {
	GetConnectTimeout() time.Duration
}

type DialOptions struct {
	ConnectTimeout  time.Duration
	Identity        string
	CallerId        string
	AppData         []byte
	StickinessToken []byte
	SdkFlowControl  bool
}

func (d DialOptions) GetConnectTimeout() time.Duration {
	return d.ConnectTimeout
}

func NewListenOptions() *ListenOptions {
	return &ListenOptions{}
}

type ListenOptions struct {
	Cost                    uint16
	Precedence              Precedence
	ConnectTimeout          time.Duration
	MaxTerminators          int
	Identity                string
	IdentitySecret          string
	BindUsingEdgeIdentity   bool
	ManualStart             bool
	SdkFlowControl          bool
	DoNotSaveDialerIdentity bool
	ListenerId              string
	KeyPair                 *kx.KeyPair
	// ConnectQueueSize bounds the maximum number of dials this listener will
	// process in parallel. Each accepted dial is handled by a worker drawn
	// from a per-listener pool of this size. Once the pool is saturated and
	// can't immediately pick up the next dial, the SDK replies DialFailed to
	// the router so it can try another terminator. Defaults to 10 when zero.
	ConnectQueueSize int
	// EventHandler receives listener lifecycle notifications. If nil, events are discarded.
	EventHandler ListenerEventHandler

	// Below: per-Listen-call wiring. Set by the caller of RouterClient.Listen.
	// These are required for a successful Listen.

	// Service identifies what to host.
	Service *rest_model.ServiceDetail
	// Session is the bind session token.
	Session *rest_model.SessionDetail
	// Env is the xgress environment factory.
	Env func() xgress.Env
	// Host is the parent listener surface used for queueing dial work,
	// delivering accepted conns, and notifying close.
	Host ListenerHost
}

func (options *ListenOptions) GetConnectTimeout() time.Duration {
	return options.ConnectTimeout
}

// Validate checks that all required per-Listen-call wiring is present.
// Returns nil when all are set, otherwise an error naming the first missing
// field.
func (options *ListenOptions) Validate() error {
	switch {
	case options.Service == nil:
		return errors.New("ListenOptions.Service is required")
	case options.Session == nil:
		return errors.New("ListenOptions.Session is required")
	case options.Env == nil:
		return errors.New("ListenOptions.Env is required")
	case options.Host == nil:
		return errors.New("ListenOptions.Host is required")
	}
	return nil
}

func (options *ListenOptions) String() string {
	return fmt.Sprintf("[ListenOptions cost=%v, max-connections=%v]", options.Cost, options.MaxTerminators)
}

// ListenerEventHandler receives notifications about listener lifecycle events from edge routers.
type ListenerEventHandler interface {
	// NotifyEstablished is called when a bind to an edge router has been confirmed.
	NotifyEstablished()
	// NotifyStartOver is called when the router indicates the listener should restart hosting.
	NotifyStartOver()
	// NotifyNotRetriable is called when the router reports a non-recoverable hosting error.
	NotifyNotRetriable()
}
