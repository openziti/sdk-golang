package network

import (
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/edgexg"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/sirupsen/logrus"
	"io"
	"time"
)

type XgAdapter struct {
	conn        *edgeConn
	readC       chan []byte
	closeNotify <-chan struct{}
	env         xgress.Env
	xg          *xgress.Xgress
}

func (self *XgAdapter) HandleXgressClose(x *xgress.Xgress) {
	self.xg.ForwardEndOfCircuit(func(payload *xgress.Payload) bool {
		self.ForwardPayload(payload, x)
		return true
	})
	self.conn.close(true)

	// see note in close
	self.conn.msgMux.RemoveMsgSink(self.conn)

	xgCloseMsg := channel.NewMessage(edge.ContentTypeXgClose, []byte(self.xg.CircuitId()))
	if err := xgCloseMsg.WithTimeout(5 * time.Second).Send(self.conn.SdkChannel.GetControlSender()); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send close xg close message")
	}
}

func (self *XgAdapter) ForwardPayload(payload *xgress.Payload, x *xgress.Xgress) {
	msg := payload.Marshall()
	msg.PutUint32Header(edge.ConnIdHeader, self.conn.Id())
	if err := self.conn.MsgChannel.GetDefaultSender().Send(msg); err != nil {
		pfxlog.Logger().WithError(err).Error("failed to send payload")
	}
}

func (self *XgAdapter) RetransmitPayload(srcAddr xgress.Address, payload *xgress.Payload) error {
	msg := payload.Marshall()
	return self.conn.MsgChannel.GetDefaultSender().Send(msg)
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

func (self *XgAdapter) GetRetransmitter() *xgress.Retransmitter {
	return self.env.GetRetransmitter()
}

func (self *XgAdapter) GetPayloadIngester() *xgress.PayloadIngester {
	return self.env.GetPayloadIngester()
}

func (self *XgAdapter) GetMetrics() xgress.Metrics {
	return self.env.GetMetrics()
}

func (self *XgAdapter) Close() error {
	return self.conn.Close()
}

func (self *XgAdapter) LogContext() string {
	return fmt.Sprintf("xg/%s", self.conn.GetCircuitId())
}

func (self *XgAdapter) Write(bytes []byte) (int, error) {
	select {
	case self.readC <- bytes:
		return len(bytes), nil
	case <-self.closeNotify:
		return 0, io.EOF
	}
}

func (self *XgAdapter) ReadPayload() ([]byte, map[uint8][]byte, error) {
	// log := pfxlog.ContextLogger(self.LogContext()).WithField("connId", self.conn.Id())

	var data []byte
	select {
	case data = <-self.readC:
	case <-self.closeNotify:
		return nil, nil, io.EOF
	}

	return data, nil, nil
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
			Error("error pushing edge message to sequencer")
		return 0, err
	}

	logrus.WithFields(edge.GetLoggerFields(msg)).Debugf("received %v bytes (msg type: %v)", len(msg.Body), msg.ContentType)
	return len(msg.Body), nil
}

func (self *XgAdapter) HandleControlMsg(controlType xgress.ControlType, headers channel.Headers, responder xgress.ControlReceiver) error {
	//TODO implement me
	panic("implement me")
}
