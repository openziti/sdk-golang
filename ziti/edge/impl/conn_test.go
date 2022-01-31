package impl

import (
	"crypto/x509"
	"github.com/openziti/channel"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/util/concurrenz"
	"github.com/openziti/foundation/util/sequencer"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func BenchmarkConnWriteBaseLine(b *testing.B) {
	testChannel := &NoopTestChannel{}

	req := require.New(b)

	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := edge.NewDataMsg(1, uint32(i), data)
		err := testChannel.Send(msg)
		req.NoError(err)
	}
}

func BenchmarkConnWrite(b *testing.B) {
	mux := edge.NewCowMapMsgMux()
	testChannel := &NoopTestChannel{}
	conn := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:      sequencer.NewNoopSequencer(4),
		msgMux:     mux,
		serviceId:  "test",
	}

	req := require.New(b)

	req.NoError(mux.AddMsgSink(conn))

	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := conn.Write(data)
		req.NoError(err)
	}
}

func BenchmarkConnRead(b *testing.B) {
	mux := edge.NewCowMapMsgMux()
	testChannel := &NoopTestChannel{}

	readQ := sequencer.NewNoopSequencer(4)
	conn := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:      readQ,
		msgMux:     mux,
		serviceId:  "test",
	}

	var stop concurrenz.AtomicBoolean
	defer stop.Set(true)

	go func() {
		counter := uint32(0)
		for !stop.Get() {
			counter += 1
			data := make([]byte, 877)
			msg := edge.NewDataMsg(1, counter, data)
			event := &edge.MsgEvent{
				ConnId: 1,
				Seq:    counter,
				Msg:    msg,
			}
			readQ.PutSequenced(counter, event)
			// mux.HandleReceive(msg, testChannel)
		}
	}()

	req := require.New(b)

	req.NoError(mux.AddMsgSink(conn))

	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := conn.Read(data)
		req.NoError(err)
	}
}

func BenchmarkSequencer(b *testing.B) {
	readQ := sequencer.NewNoopSequencer(4)

	var stop concurrenz.AtomicBoolean
	defer stop.Set(true)

	go func() {
		counter := uint32(0)
		for !stop.Get() {
			counter += 1
			data := make([]byte, 877)
			msg := edge.NewDataMsg(1, counter, data)
			event := &edge.MsgEvent{
				ConnId: 1,
				Seq:    counter,
				Msg:    msg,
			}
			readQ.PutSequenced(counter, event)
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readQ.GetNext()
	}
}

type NoopTestChannel struct {
}

func (ch *NoopTestChannel) Underlay() channel.Underlay {
	//TODO implement me
	panic("implement me")
}

func (ch *NoopTestChannel) StartRx() {
}

func (ch *NoopTestChannel) Id() *identity.TokenId {
	panic("implement Id()")
}

func (ch *NoopTestChannel) LogicalName() string {
	panic("implement LogicalName()")
}

func (ch *NoopTestChannel) ConnectionId() string {
	panic("implement ConnectionId()")
}

func (ch *NoopTestChannel) Certificates() []*x509.Certificate {
	panic("implement Certificates()")
}

func (ch *NoopTestChannel) Label() string {
	return "testchannel"
}

func (ch *NoopTestChannel) SetLogicalName(string) {
	panic("implement SetLogicalName")
}

func (ch *NoopTestChannel) Send(channel.Sendable) error {
	return nil
}

func (ch *NoopTestChannel) Close() error {
	panic("implement Close")
}

func (ch *NoopTestChannel) IsClosed() bool {
	panic("implement IsClosed")
}

func (ch *NoopTestChannel) GetTimeSinceLastRead() time.Duration {
	return 0
}
