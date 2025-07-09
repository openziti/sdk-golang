package network

import (
	"crypto/x509"
	"encoding/binary"
	"github.com/openziti/channel/v4"
	"github.com/openziti/foundation/v2/sequencer"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkConnWriteBaseLine(b *testing.B) {
	testChannel := &NoopTestChannel{}

	req := require.New(b)

	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := edge.NewDataMsg(1, data)
		err := testChannel.Send(msg)
		req.NoError(err)
	}
}

func BenchmarkConnWrite(b *testing.B) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	mux := edge.NewCowMapMsgMux()
	testChannel := edge.NewSingleSdkChannel(&NoopTestChannel{})
	conn := &edgeConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:       NewNoopSequencer[*channel.Message](closeNotify, 4),
		msgMux:      mux,
		serviceName: "test",
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
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	mux := edge.NewCowMapMsgMux()
	testChannel := edge.NewSingleSdkChannel(&NoopTestChannel{})

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
	conn := &edgeConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:       readQ,
		msgMux:      mux,
		serviceName: "test",
	}

	var stop atomic.Bool
	defer stop.Store(true)

	go func() {
		counter := uint32(0)
		for !stop.Load() {
			counter += 1
			data := make([]byte, 877)
			msg := edge.NewDataMsg(1, data)
			err := readQ.PutSequenced(msg)
			if err != nil {
				panic(err)
			}
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

	var stop atomic.Bool
	defer stop.Store(true)

	go func() {
		counter := uint32(0)
		for !stop.Load() {
			counter += 1
			data := make([]byte, 877)
			msg := edge.NewDataMsg(1, data)
			event := &edge.MsgEvent{
				ConnId: 1,
				Seq:    counter,
				Msg:    msg,
			}
			err := readQ.PutSequenced(counter, event)
			if err != nil {
				panic(err)
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readQ.GetNext()
	}
}

func TestReadMultipart(t *testing.T) {
	req := require.New(t)

	closeNotify := make(chan struct{})
	defer close(closeNotify)

	mux := edge.NewCowMapMsgMux()
	testChannel := edge.NewSingleSdkChannel(&NoopTestChannel{})

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
	conn := &edgeConn{
		MsgChannel:  *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:       readQ,
		msgMux:      mux,
		serviceName: "test",
	}

	var stop atomic.Bool
	defer stop.Store(true)

	var multipart []byte
	words := []string{"Hello", "World", "of", "ziti"}
	for _, w := range words {
		multipart = binary.LittleEndian.AppendUint16(multipart, uint16(len(w)))
		multipart = append(multipart, []byte(w)...)
	}
	msg := edge.NewDataMsg(1, multipart)
	msg.Headers.PutUint32Header(edge.FlagsHeader, uint32(edge.MULTIPART_MSG))
	_ = readQ.PutSequenced(msg)
	msg = edge.NewDataMsg(1, nil)
	msg.Headers.PutUint32Header(edge.FlagsHeader, uint32(edge.FIN))
	err := readQ.PutSequenced(msg)
	if err != nil {
		panic(err)
	}

	var read []string
	for {
		data := make([]byte, 1024)
		req.NoError(conn.SetReadDeadline(time.Now().Add(1 * time.Second)))
		n, e := conn.Read(data)
		if e == io.EOF {
			break
		}

		req.NoError(e)

		read = append(read, string(data[:n]))
	}

	req.Equal(words, read)
}

type NoopTestChannel struct {
}

func (ch *NoopTestChannel) GetUnderlays() []channel.Underlay {
	panic("implement me")
}

func (ch *NoopTestChannel) GetUnderlayCountsByType() map[string]int {
	panic("implement me")
}

func (ch *NoopTestChannel) GetUserData() interface{} {
	return nil
}

func (ch *NoopTestChannel) Headers() map[int32][]byte {
	return nil
}

func (ch *NoopTestChannel) TrySend(s channel.Sendable) (bool, error) {
	panic("implement me")
}

func (ch *NoopTestChannel) Underlay() channel.Underlay {
	panic("implement me")
}

func (ch *NoopTestChannel) StartRx() {
}

func (ch *NoopTestChannel) Id() string {
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
