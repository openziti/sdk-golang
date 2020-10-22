package impl

import (
	"crypto/x509"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/util/concurrenz"
	"github.com/openziti/foundation/util/sequencer"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type testChannel struct {
}

func (ch *testChannel) Id() *identity.TokenId {
	panic("implement me")
}

func (ch *testChannel) LogicalName() string {
	panic("implement me")
}

func (ch *testChannel) ConnectionId() string {
	panic("implement me")
}

func (ch *testChannel) Certificates() []*x509.Certificate {
	panic("implement me")
}

func (ch *testChannel) Label() string {
	panic("implement me")
}

func (ch *testChannel) SetLogicalName(logicalName string) {
	panic("implement me")
}

func (ch *testChannel) Bind(h channel2.BindHandler) error {
	panic("implement me")
}

func (ch *testChannel) AddPeekHandler(h channel2.PeekHandler) {
	panic("implement me")
}

func (ch *testChannel) AddTransformHandler(h channel2.TransformHandler) {
	panic("implement me")
}

func (ch *testChannel) AddReceiveHandler(h channel2.ReceiveHandler) {
	panic("implement me")
}

func (ch *testChannel) AddErrorHandler(h channel2.ErrorHandler) {
	panic("implement me")
}

func (ch *testChannel) AddCloseHandler(h channel2.CloseHandler) {
	panic("implement me")
}

func (ch *testChannel) SetUserData(data interface{}) {
	panic("implement me")
}

func (ch *testChannel) GetUserData() interface{} {
	panic("implement me")
}

func (ch *testChannel) Send(m *channel2.Message) error {
	return nil
}

func (ch *testChannel) SendWithPriority(m *channel2.Message, p channel2.Priority) error {
	return nil
}

func (ch *testChannel) SendAndSync(m *channel2.Message) (chan error, error) {
	return ch.SendAndSyncWithPriority(m, channel2.Standard)
}

func (ch *testChannel) SendAndSyncWithPriority(m *channel2.Message, p channel2.Priority) (chan error, error) {
	result := make(chan error, 1)
	result <- nil
	return result, nil
}

func (ch *testChannel) SendWithTimeout(m *channel2.Message, timeout time.Duration) error {
	return nil
}

func (ch *testChannel) SendPrioritizedWithTimeout(m *channel2.Message, p channel2.Priority, timeout time.Duration) error {
	return nil
}

func (ch *testChannel) SendAndWaitWithTimeout(m *channel2.Message, timeout time.Duration) (*channel2.Message, error) {
	panic("implement me")
}

func (ch *testChannel) SendPrioritizedAndWaitWithTimeout(m *channel2.Message, p channel2.Priority, timeout time.Duration) (*channel2.Message, error) {
	panic("implement me")
}

func (ch *testChannel) SendAndWait(m *channel2.Message) (chan *channel2.Message, error) {
	panic("implement me")
}

func (ch *testChannel) SendAndWaitWithPriority(m *channel2.Message, p channel2.Priority) (chan *channel2.Message, error) {
	panic("implement me")
}

func (ch *testChannel) SendForReply(msg channel2.TypedMessage, timeout time.Duration) (*channel2.Message, error) {
	panic("implement me")
}

func (ch *testChannel) SendForReplyAndDecode(msg channel2.TypedMessage, timeout time.Duration, result channel2.TypedMessage) error {
	return nil
}

func (ch *testChannel) Close() error {
	panic("implement me")
}

func (ch *testChannel) IsClosed() bool {
	panic("implement me")
}

func (ch *testChannel) Underlay() channel2.Underlay {
	panic("implement me")
}

func BenchmarkConnWriteBaseLine(b *testing.B) {
	testChannel := &testChannel{}

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
	mux := edge.NewMsgMux()
	testChannel := &testChannel{}
	conn := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:      sequencer.NewSingleWriterSeq(DefaultMaxOutOfOrderMsgs),
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
	mux := edge.NewMsgMux()
	testChannel := &testChannel{}
	conn := &edgeConn{
		MsgChannel: *edge.NewEdgeMsgChannel(testChannel, 1),
		readQ:      sequencer.NewSingleWriterSeq(DefaultMaxOutOfOrderMsgs),
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
			mux.HandleReceive(msg, testChannel)
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
