package network

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/foundation/v2/sequencer"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
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

	mux := edge.NewChannelConnMapMux[any](nil)
	testChannel := edge.NewSingleSdkChannel(&NoopTestChannel{})
	conn := &edgeConnLegacy{
		edgeConnBase: edgeConnBase{serviceName: "test"},
		msgCh:        *edge.NewEdgeMsgChannel(testChannel, 1),
		mux:          mux,
		readQ:        NewNoopSequencer[*channel.Message](closeNotify, 4),
	}
	conn.initChunkReader()

	req := require.New(b)

	req.NoError(mux.Add(conn))

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

	mux := edge.NewChannelConnMapMux[any](nil)
	testChannel := edge.NewSingleSdkChannel(&NoopTestChannel{})

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
	conn := &edgeConnLegacy{
		edgeConnBase: edgeConnBase{serviceName: "test"},
		msgCh:        *edge.NewEdgeMsgChannel(testChannel, 1),
		mux:          mux,
		readQ:        readQ,
	}
	conn.initChunkReader()

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

	req.NoError(mux.Add(conn))

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

	mux := edge.NewChannelConnMapMux[any](nil)
	testChannel := edge.NewSingleSdkChannel(&NoopTestChannel{})

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
	conn := &edgeConnLegacy{
		edgeConnBase: edgeConnBase{serviceName: "test"},
		msgCh:        *edge.NewEdgeMsgChannel(testChannel, 1),
		mux:          mux,
		readQ:        readQ,
	}
	conn.initChunkReader()

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

func TestChunkReaderRejectsMultipartFlagLibsodium(t *testing.T) {
	r := newEdgeChunkReader(func() ([]byte, uint32, error) {
		return []byte{1, 0, 'a'}, edge.MULTIPART_MSG, nil
	}, func() *logrus.Entry { return logrus.NewEntry(logrus.StandardLogger()) })
	r.SetRxKey(make([]byte, 32))

	_, err := r.Read(make([]byte, 16))
	require.ErrorContains(t, err, "multipart message on an encrypted connection")
}

// TestHostChildConnMultipartAdvertisement verifies that an encrypted hosted conn does not advertise
// MULTIPART on its first message, so a C SDK peer never sends MULTIPART_MSG to it. A plain conn
// still does.
func TestHostChildConnMultipartAdvertisement(t *testing.T) {
	for _, crypto := range []bool{true, false} {
		t.Run(fmt.Sprintf("crypto=%v", crypto), func(t *testing.T) {
			req := require.New(t)
			name := "multipart-test"
			wire := newWireChannel()
			sent := make(chan *channel.Message, 1)
			wire.setDeliver(func(msg *channel.Message) { sent <- msg })
			hostConn := newWiredHostConn(1, &rest_model.ServiceDetail{Name: &name}, wire)

			child, err := hostConn.buildChildConn(childConnParams{id: 2, crypto: crypto}, false, nil)
			req.NoError(err)
			_, err = child.(*edgeConnLegacy).msgCh.Write([]byte("x"))
			req.NoError(err)

			flags, _ := (<-sent).GetUint32Header(edge.FlagsHeader)
			req.Equal(!crypto, flags&edge.MULTIPART != 0)
		})
	}
}

// TestDialConnMultipartAdvertisement verifies that an encrypted dialed conn does not advertise
// MULTIPART on its first message. A plain conn still does.
func TestDialConnMultipartAdvertisement(t *testing.T) {
	for _, crypto := range []bool{true, false} {
		t.Run(fmt.Sprintf("crypto=%v", crypto), func(t *testing.T) {
			req := require.New(t)
			wire := newWireChannel()
			sent := make(chan *channel.Message, 1)
			wire.setDeliver(func(msg *channel.Message) { sent <- msg })
			rc := &routerConn{ch: edge.NewSingleSdkChannel(wire), mux: edge.NewChannelConnMapMux[any](nil)}
			pending := newPendingMsgSink(2)
			req.NoError(rc.mux.Add(pending))

			// the reply carries no host key, so the crypto setup leaves the conn unencrypted
			reply := channel.NewMessage(edge.ContentTypeStateConnected, nil)
			logger := logrus.NewEntry(logrus.StandardLogger())
			conn, err := rc.buildV1LegacyConn(logger, reply, pending, 2, "", "", nil, nil, crypto, "multipart-test")
			req.NoError(err)
			_, err = conn.(*edgeConnLegacy).msgCh.Write([]byte("x"))
			req.NoError(err)

			flags, _ := (<-sent).GetUint32Header(edge.FlagsHeader)
			req.Equal(!crypto, flags&edge.MULTIPART != 0)
		})
	}
}

type NoopTestChannel struct {
}

func (ch *NoopTestChannel) CloseNotify() <-chan struct{} {
	panic("implement me")
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

func (ch *NoopTestChannel) AcceptUnderlay(channel.Underlay) error {
	return nil
}

func (ch *NoopTestChannel) GetSenders() channel.Senders {
	return nil
}
