package network

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/edgexg"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
)

// defaultSendTimeout bounds each send the xgress gives no deadline: teardown sends, the end of a data stream
// and retransmissions.
const defaultSendTimeout = 5 * time.Second

// errXgressClosed is returned for a retransmission requested after the xgress closed.
var errXgressClosed = errors.New("xgress closed")

type XgAdapter struct {
	conn         *edgeConn
	readC        chan []byte
	env          xgress.Env
	xg           *xgress.Xgress
	writeAdapter *xgress.WriteAdapter
	// sendTimeout overrides defaultSendTimeout when set.
	sendTimeout  time.Duration
	teardownLock sync.Mutex
	// lastTeardown is closed when the most recently queued teardown send has finished.
	lastTeardown chan struct{}
}

// queueTeardown runs send on its own goroutine once the previously queued teardown send has finished, with
// a context bounded by the send timeout. Closing the xgress therefore never waits for the wire, and the
// router still receives end of circuit before the close notice, as it drops an end of circuit that arrives
// after the close notice.
func (self *XgAdapter) queueTeardown(send func(ctx context.Context)) {
	timeout := self.getSendTimeout()

	self.teardownLock.Lock()
	prev := self.lastTeardown
	done := make(chan struct{})
	self.lastTeardown = done
	self.teardownLock.Unlock()

	go func() {
		defer close(done)
		if prev != nil {
			<-prev
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		send(ctx)
	}()
}

func (self *XgAdapter) getSendTimeout() time.Duration {
	if self.sendTimeout == 0 {
		return defaultSendTimeout
	}
	return self.sendTimeout
}

func (self *XgAdapter) HandleXgressClose(x *xgress.Xgress) {
	circuitId := self.xg.CircuitId()
	self.queueTeardown(func(ctx context.Context) {
		xgCloseMsg := channel.NewMessage(edge.ContentTypeXgClose, []byte(circuitId))
		// The timeout bounds only the wait for queue space; once queued the notice is written however long the
		// queue takes, since its context ends when this returns.
		if err := xgCloseMsg.WithContext(ctx).SendAndWaitForQueue(self.conn.GetControlSender()); err != nil {
			pfxlog.Logger().WithError(err).Error("failed to send close xg close message")
		}
	})

	// see note in close
	self.conn.msgMux.Remove(self.conn)
}

func (self *XgAdapter) ForwardPayload(payload *xgress.Payload, x *xgress.Xgress, ctx context.Context) {
	msg := payload.Marshall()
	msg.PutUint32Header(edge.ConnIdHeader, self.conn.Id())

	if payload.IsCircuitEndFlagSet() {
		// Xgress.Close marks the xgress closed before sending its end of circuit, waits for the send before
		// running its close handlers, and can run on the router channel's receive goroutine, so that send is
		// queued. An end of circuit from an open xgress instead ends the data stream for a peer without EOF
		// support. It is buffered and retransmitted like data, and the buffer marks it sent once this returns,
		// so it is sent here, within the send timeout.
		if x.Closed() {
			self.queueTeardown(func(ctx context.Context) {
				if err := msg.WithContext(ctx).SendAndWaitForWire(self.conn.GetDefaultSender()); err != nil {
					pfxlog.Logger().WithField("circuitId", payload.CircuitId).WithError(err).Error("failed to send end of circuit")
				}
			})
			return
		}
		if ctx == nil {
			ctx = context.Background()
		}
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, self.getSendTimeout())
			defer cancel()
		}
	}

	if err := msg.WithContext(ctx).SendAndWaitForWire(self.conn.GetDefaultSender()); err != nil {
		pfxlog.Logger().WithField("circuitId", payload.CircuitId).WithError(err).Error("failed to send payload")
	}
}

// RetransmitPayload queues payload to be sent again, waiting at most the send timeout for queue space, so a
// router that has stopped reading can't hold the send buffer's retransmit goroutine; a payload that times out
// is retried on a later scan. It refuses once the xgress has closed.
func (self *XgAdapter) RetransmitPayload(srcAddr xgress.Address, payload *xgress.Payload) error {
	if self.xg.Closed() {
		return errXgressClosed
	}

	msg := payload.Marshall()
	if err := msg.WithTimeout(self.getSendTimeout()).SendAndWaitForQueue(self.conn.GetDefaultSender()); err != nil {
		// if the channel is closed, close the xgress
		if self.conn.MsgChannel.GetChannel().IsClosed() {
			self.xg.Close()
		}
		return err
	}
	return nil
}

func (self *XgAdapter) ForwardControlMessage(control *xgress.Control, x *xgress.Xgress) {
	msg := control.Marshall()
	if err := self.conn.MsgChannel.GetDefaultSender().Send(msg); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to forward control message")
	}
}

func (self *XgAdapter) ForwardAcknowledgement(ack *xgress.Acknowledgement, address xgress.Address) {
	msg := ack.Marshall()
	if err := self.conn.MsgChannel.GetDefaultSender().Send(msg); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send acknowledgement")
	}
}

func (self *XgAdapter) GetPayloadIngester() *xgress.PayloadIngester {
	return self.env.GetPayloadIngester()
}

func (self *XgAdapter) GetMetrics() xgress.Metrics {
	return self.env.GetMetrics()
}

func (self *XgAdapter) Close() error {
	return nil
}

func (self *XgAdapter) LogContext() string {
	return fmt.Sprintf("xg/%s", self.conn.GetCircuitId())
}

func (self *XgAdapter) ReadPayload() ([]byte, map[uint8][]byte, error) {
	return nil, nil, errors.New("should never be called")
}

func (self *XgAdapter) WritePayload(bytes []byte, headers map[uint8][]byte) (int, error) {
	var msgUUID []byte
	var edgeHdrs map[int32][]byte

	if headers != nil {
		msgUUID = headers[xgress.HeaderKeyUUID]

		edgeHdrs = make(map[int32][]byte)
		for k, v := range headers {
			if edgeHeader, found := edgexg.HeadersFromFabric[k]; found {
				edgeHdrs[edgeHeader] = v
			}
		}
	}

	msg := edge.NewDataMsg(self.conn.Id(), bytes)
	if msgUUID != nil {
		msg.Headers[edge.UUIDHeader] = msgUUID
	}

	for k, v := range edgeHdrs {
		msg.Headers[k] = v
	}

	if err := self.conn.readQ.PutSequenced(msg); err != nil {
		logrus.WithFields(edge.GetLoggerFields(msg)).WithError(err).
			WithField("circuitId", self.conn.circuitId).
			Error("error pushing edge message to sequencer")
		return 0, err
	}

	logrus.WithFields(edge.GetLoggerFields(msg)).Debugf("received %v bytes (msg type: %v)", len(msg.Body), msg.ContentType)
	return len(msg.Body), nil
}

func (self *XgAdapter) FlowFromFabricToXgressClosed() {
	pfxlog.Logger().WithField("circuitId", self.conn.circuitId).
		Debug("fabric to sdk flow complete")
	self.conn.readQ.Close()
}

func (self *XgAdapter) HandleControlMsg(controlType xgress.ControlType, headers channel.Headers, responder xgress.ControlReceiver) error {
	//TODO implement me
	panic("implement me")
}
