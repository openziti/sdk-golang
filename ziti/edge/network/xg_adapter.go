package network

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
)

type XgAdapter struct {
	sender       RouterSender
	connId       uint32
	circuitId    string
	mux          edge.ConnMux[any]
	muxSink      edge.MsgSink[any]
	ctrlSender   channel.Sender
	env          xgress.Env
	xg           *xgress.Xgress
	writeAdapter *xgress.WriteAdapter
}

func (self *XgAdapter) HandleXgressClose(x *xgress.Xgress) {
	xgCloseMsg := channel.NewMessage(edge.ContentTypeXgClose, []byte(self.xg.CircuitId()))
	if err := xgCloseMsg.WithTimeout(5 * time.Second).Send(self.ctrlSender); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send close xg close message")
	}

	// The xgress is fully closed, so no more data will flow in either direction.
	// Mark the owning conn closed so IsClosed reflects it. This is the single
	// point that covers every teardown that ends at the xgress: an app-initiated
	// Close, a peer end-of-circuit (e.g. the host's access being revoked), or a
	// router StateClosed that drains and then closes. Without this the conn would
	// report open until the underlying channel went away. close is idempotent, so
	// the app-initiated path (which calls close first) is unaffected.
	if conn, ok := self.muxSink.(*edgeConnXgress); ok {
		conn.close(false)
	}

	// see note in close
	self.mux.Remove(self.muxSink)
}

func (self *XgAdapter) ForwardPayload(payload *xgress.Payload, _ *xgress.Xgress, ctx context.Context) {
	msg := payload.Marshall()
	msg.PutUint32Header(edge.ConnIdHeader, self.connId)

	if err := self.sender.SendPayload(msg, ctx); err != nil {
		pfxlog.Logger().WithField("circuitId", payload.CircuitId).WithError(err).Error("failed to send payload")
	}
}

func (self *XgAdapter) RetransmitPayload(srcAddr xgress.Address, payload *xgress.Payload) error {
	msg := payload.Marshall()
	if err := self.sender.SendPayload(msg, context.Background()); err != nil {
		// if the channel is closed, close the xgress
		if self.sender.IsClosed() {
			self.xg.Close()
		}
		return err
	}
	return nil
}

func (self *XgAdapter) ForwardControlMessage(control *xgress.Control, x *xgress.Xgress) {
	msg := control.Marshall()
	if err := self.sender.SendControlMessage(msg); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to forward control message")
	}
}

func (self *XgAdapter) ForwardAcknowledgement(ack *xgress.Acknowledgement, address xgress.Address) {
	msg := ack.Marshall()
	if err := self.sender.SendAcknowledgement(msg); err != nil {
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
	return fmt.Sprintf("xg/%s", self.circuitId)
}

func (self *XgAdapter) ReadPayload() ([]byte, map[uint8][]byte, error) {
	return nil, nil, errors.New("should never be called")
}

func (self *XgAdapter) WritePayload([]byte, map[uint8][]byte) (int, error) {
	return 0, errors.New("not available in pull mode")
}

func (self *XgAdapter) FlowFromFabricToXgressClosed() {
	// no-op: in pull mode, ReadAdapter handles cleanup
}

func (self *XgAdapter) HandleControlMsg(controlType xgress.ControlType, headers channel.Headers, responder xgress.ControlReceiver) error {
	//TODO implement me
	panic("implement me")
}
