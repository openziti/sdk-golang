package impl

import (
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/util/concurrenz"
	"github.com/openziti/foundation/util/sequencer"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
	"testing"
)

func BenchmarkConnWriteBaseLine(b *testing.B) {
	testChannel := &channel2.NoopTestChannel{}

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
	testChannel := &channel2.NoopTestChannel{}
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
	testChannel := &channel2.NoopTestChannel{}

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
