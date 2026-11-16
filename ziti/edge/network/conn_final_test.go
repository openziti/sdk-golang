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

package network

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/secretstream"
	"github.com/openziti/sdk-golang/v2/secretstream/kx"
	"github.com/openziti/sdk-golang/v2/xgress"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// testChunk is one chunk handed to an edgeChunkReader by a test source.
type testChunk struct {
	data  []byte
	flags uint32
}

// encryptedTestStream produces the chunks one side of an encrypted connection sends and a reader
// set up to receive them.
type encryptedTestStream struct {
	t      *testing.T
	sender secretstream.Encryptor
	chunks []testChunk
	reader *edgeChunkReader
}

// newEncryptedTestStream returns a stream whose reader has been given the session key. Once the
// queued chunks run out the reader's source reports sourceErr, standing in for whatever ends the
// connection underneath: nil blocks the test instead, since no chunk should be asked for.
func newEncryptedTestStream(t *testing.T, sourceErr error) *encryptedTestStream {
	t.Helper()
	key, err := secretstream.NewStreamKey()
	require.NoError(t, err)

	sender, header, err := secretstream.NewEncryptor(key)
	require.NoError(t, err)

	s := &encryptedTestStream{t: t, sender: sender}
	s.chunks = append(s.chunks, testChunk{data: header})
	s.reader = newEdgeChunkReader(func() ([]byte, uint32, error) {
		if len(s.chunks) == 0 {
			if sourceErr == nil {
				t.Fatal("read past the end of the test stream")
			}
			return nil, 0, sourceErr
		}
		next := s.chunks[0]
		s.chunks = s.chunks[1:]
		return next.data, next.flags, nil
	}, func() *logrus.Entry {
		return logrus.NewEntry(logrus.StandardLogger())
	})
	s.reader.SetRxKey(key)
	return s
}

// push queues data encrypted with tag, carried by a message with the given edge flags.
func (s *encryptedTestStream) push(data string, tag byte, flags uint32) {
	s.t.Helper()
	cipherData, err := s.sender.Push([]byte(data), tag)
	require.NoError(s.t, err)
	s.chunks = append(s.chunks, testChunk{data: cipherData, flags: flags})
}

// fin queues a FIN with no body, which needs no key to produce.
func (s *encryptedTestStream) fin() {
	s.chunks = append(s.chunks, testChunk{flags: edge.FIN})
}

func (s *encryptedTestStream) requireRead(expected string) {
	s.t.Helper()
	buf := make([]byte, 64)
	n, err := s.reader.Read(buf)
	require.NoError(s.t, err)
	require.Equal(s.t, expected, string(buf[:n]))
}

func (s *encryptedTestStream) requireReadErr(expected error) {
	s.t.Helper()
	n, err := s.reader.Read(make([]byte, 64))
	require.Equal(s.t, 0, n)
	require.ErrorIs(s.t, err, expected)
}

// A peer that tags its chunks ends its stream with a TagFinal chunk. A FIN without one can come
// from anything on the path, so it is reported as a truncation, and keeps being reported as one.
func Test_ChunkReader_FinWithoutFinalIsTruncation(t *testing.T) {
	s := newEncryptedTestStream(t, nil)
	s.push("hello", secretstream.TagPush, 0)
	s.fin()

	s.requireRead("hello")
	s.requireReadErr(io.ErrUnexpectedEOF)
	s.requireReadErr(io.ErrUnexpectedEOF)
}

// The same holds when the FIN rides on a message that carries data.
func Test_ChunkReader_FinOnDataWithoutFinalIsTruncation(t *testing.T) {
	s := newEncryptedTestStream(t, nil)
	s.push("hello", secretstream.TagPush, edge.FIN)

	s.requireRead("hello")
	s.requireReadErr(io.ErrUnexpectedEOF)
}

// The connection ending underneath a tagging peer's stream, with no FIN at all, is a truncation too.
func Test_ChunkReader_SourceEndWithoutFinalIsTruncation(t *testing.T) {
	for _, sourceErr := range []error{io.EOF, ErrClosed} {
		s := newEncryptedTestStream(t, sourceErr)
		s.push("hello", secretstream.TagPush, 0)

		s.requireRead("hello")
		s.requireReadErr(io.ErrUnexpectedEOF)
		s.requireReadErr(io.ErrUnexpectedEOF)
	}
}

// A TagFinal chunk is an authenticated end of stream: the reader reports io.EOF, without first
// returning an empty read, whether the FIN follows in its own message or the stream just ends.
func Test_ChunkReader_FinalIsEOF(t *testing.T) {
	t.Run("final then fin", func(t *testing.T) {
		s := newEncryptedTestStream(t, nil)
		s.push("hello", secretstream.TagPush, 0)
		s.push("", secretstream.TagFinal, 0)
		s.fin()

		s.requireRead("hello")
		s.requireReadErr(io.EOF)
		s.requireReadErr(io.EOF)
		require.Len(t, s.chunks, 1, "the reader went on reading after the end of the stream")
	})

	t.Run("final in the fin message", func(t *testing.T) {
		s := newEncryptedTestStream(t, nil)
		s.push("hello", secretstream.TagPush, 0)
		s.push("", secretstream.TagFinal, edge.FIN)

		s.requireRead("hello")
		s.requireReadErr(io.EOF)
	})

	t.Run("final with nothing sent before it", func(t *testing.T) {
		s := newEncryptedTestStream(t, nil)
		s.push("", secretstream.TagFinal, 0)

		s.requireReadErr(io.EOF)
	})

	t.Run("final carrying data", func(t *testing.T) {
		s := newEncryptedTestStream(t, nil)
		s.push("bye", secretstream.TagFinal, 0)

		s.requireRead("bye")
		s.requireReadErr(io.EOF)
	})
}

// A peer that only sends TagMessage predates the convention. Its FIN, or its connection ending,
// is still an ordinary end of stream.
func Test_ChunkReader_UntaggedPeerFinIsEOF(t *testing.T) {
	t.Run("fin", func(t *testing.T) {
		s := newEncryptedTestStream(t, nil)
		s.push("hello", secretstream.TagMessage, 0)
		s.fin()

		s.requireRead("hello")
		s.requireReadErr(io.EOF)
	})

	t.Run("source end", func(t *testing.T) {
		s := newEncryptedTestStream(t, ErrClosed)
		s.push("hello", secretstream.TagMessage, 0)

		s.requireRead("hello")
		s.requireReadErr(io.EOF)
	})
}

// Nothing follows the end of the stream. The reader stops at a TagFinal, so this takes a caller
// that reads on regardless; a chunk that turns up then is an error, not data.
func Test_ChunkReader_DataAfterFinalRejected(t *testing.T) {
	s := newEncryptedTestStream(t, nil)
	s.push("bye", secretstream.TagFinal, 0)
	s.push("more", secretstream.TagPush, 0)

	s.requireRead("bye")
	s.reader.readFIN.Store(false)

	n, err := s.reader.Read(make([]byte, 64))
	require.Equal(t, 0, n)
	require.Error(t, err)
	require.NotErrorIs(t, err, io.EOF)
}

// A stream this side closed itself was not cut short by anyone else.
func Test_ChunkReader_LocalCloseIsEOF(t *testing.T) {
	s := newEncryptedTestStream(t, ErrClosed)
	s.push("hello", secretstream.TagPush, 0)

	s.requireRead("hello")
	s.reader.MarkLocalClose()
	s.reader.MarkFIN()
	s.requireReadErr(io.EOF)
}

// recordingTestChannel reports everything sent on it as written and keeps the messages.
type recordingTestChannel struct {
	unackedTestChannel
	lock sync.Mutex
	msgs []*channel.Message
}

func newRecordingTestChannel() *recordingTestChannel {
	return &recordingTestChannel{unackedTestChannel: unackedTestChannel{closeNotify: make(chan struct{})}}
}

func (ch *recordingTestChannel) Send(s channel.Sendable) error {
	ch.lock.Lock()
	ch.msgs = append(ch.msgs, s.Msg())
	ch.lock.Unlock()
	return ch.unackedTestChannel.Send(s)
}

func (ch *recordingTestChannel) TrySend(s channel.Sendable) (bool, error) {
	return true, ch.Send(s)
}

// take returns the messages sent since the last call.
func (ch *recordingTestChannel) take() []*channel.Message {
	ch.lock.Lock()
	defer ch.lock.Unlock()
	msgs := ch.msgs
	ch.msgs = nil
	return msgs
}

// newEncryptedLegacyPair returns two legacy conns that have completed the key exchange. What
// sender writes is recorded on the returned channel; the test decides what receiver gets to see,
// as a router between the two would.
func newEncryptedLegacyPair(t *testing.T) (*edgeConnLegacy, *recordingTestChannel, *edgeConnLegacy, edge.SdkChannel) {
	t.Helper()
	senderCh := newRecordingTestChannel()
	sender := newLegacyTestConn(t, edge.NewChannelConnMapMux[any](nil), edge.NewSingleSdkChannel(senderCh), 1)

	receiverCh := edge.NewSingleSdkChannel(newRecordingTestChannel())
	receiver := newLegacyTestConn(t, edge.NewChannelConnMapMux[any](nil), receiverCh, 1)

	senderKeys, err := kx.NewKeyPair()
	require.NoError(t, err)
	receiverKeys, err := kx.NewKeyPair()
	require.NoError(t, err)

	require.NoError(t, sender.establishClientCrypto(senderKeys, receiverKeys.Public(), edge.CryptoMethodLibsodium))
	_, err = receiver.establishServerCrypto(receiverKeys, senderKeys.Public(), edge.CryptoMethodLibsodium)
	require.NoError(t, err)

	return sender, senderCh, receiver, receiverCh
}

func requireConnRead(t *testing.T, conn edge.Conn, expected string) {
	t.Helper()
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, expected, string(buf[:n]))
}

// stalledTestChannel works like unackedTestChannel until stall is called. From then on nothing
// sent on it reaches the wire: Send waits until the sendable gives up.
type stalledTestChannel struct {
	unackedTestChannel
	stalled atomic.Bool
	waiting chan struct{}
	release chan struct{}
}

func newStalledTestChannel(t *testing.T) *stalledTestChannel {
	ch := &stalledTestChannel{
		unackedTestChannel: unackedTestChannel{closeNotify: make(chan struct{})},
		waiting:            make(chan struct{}, 16),
		release:            make(chan struct{}),
	}
	// lets go of senders that wait without a timeout
	t.Cleanup(func() { close(ch.release) })
	return ch
}

func (ch *stalledTestChannel) stall() {
	ch.stalled.Store(true)
}

func (ch *stalledTestChannel) Send(s channel.Sendable) error {
	if !ch.stalled.Load() {
		return ch.unackedTestChannel.Send(s)
	}
	ch.waiting <- struct{}{}
	select {
	case <-s.Context().Done():
		return s.Context().Err()
	case <-ch.release:
		return errors.New("channel closed")
	}
}

func (ch *stalledTestChannel) TrySend(s channel.Sendable) (bool, error) {
	return true, ch.Send(s)
}

// Ending the encrypted stream does not let Close of a legacy conn wait on the edge channel any
// longer than sending StateClosed does.
func Test_LegacyConn_CloseIsBoundedOnStalledChannel(t *testing.T) {
	newConn := func(t *testing.T) (*edgeConnLegacy, *stalledTestChannel) {
		t.Helper()
		ch := newStalledTestChannel(t)
		conn := newLegacyTestConn(t, edge.NewChannelConnMapMux[any](nil), edge.NewSingleSdkChannel(ch), 1)

		keys, err := kx.NewKeyPair()
		require.NoError(t, err)
		peerKeys, err := kx.NewKeyPair()
		require.NoError(t, err)
		require.NoError(t, conn.establishClientCrypto(keys, peerKeys.Public(), edge.CryptoMethodLibsodium))

		_, err = conn.Write([]byte("hello"))
		require.NoError(t, err)
		return conn, ch
	}

	requireCloseReturns := func(t *testing.T, conn *edgeConnLegacy) {
		t.Helper()
		start := time.Now()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = conn.Close()
		}()

		select {
		case <-done:
		case <-time.After(edge.StateTimeout + 3*time.Second):
			t.Fatalf("Close has not returned after %v", time.Since(start))
		}
		require.True(t, conn.IsClosed())
	}

	t.Run("stalled channel", func(t *testing.T) {
		t.Parallel()
		conn, ch := newConn(t)
		ch.stall()

		requireCloseReturns(t, conn)
	})

	t.Run("write in progress", func(t *testing.T) {
		t.Parallel()
		conn, ch := newConn(t)
		ch.stall()

		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = conn.Write([]byte("stuck"))
		}()

		select {
		case <-ch.waiting:
		case <-time.After(5 * time.Second):
			t.Fatal("Write did not reach the channel")
		}

		requireCloseReturns(t, conn)

		select {
		case <-writeDone:
			t.Fatal("Write was expected to still wait for the channel")
		default:
		}
	})
}

// What a legacy conn sends when it half-closes or closes lets its peer read to a clean io.EOF.
func Test_LegacyConn_CloseEndsEncryptedStream(t *testing.T) {
	t.Run("CloseWrite", func(t *testing.T) {
		req := require.New(t)
		sender, senderCh, receiver, receiverCh := newEncryptedLegacyPair(t)

		_, err := sender.Write([]byte("hello"))
		req.NoError(err)
		req.NoError(sender.CloseWrite())
		_, err = sender.Write([]byte("more"))
		req.Error(err)

		msgs := senderCh.take()
		req.Len(msgs, 4, "expected the crypto header, the data, the final chunk and the FIN")
		req.Len(msgs[2].Body, secretstream.StreamABytes, "the final chunk carries no data")
		for _, msg := range msgs {
			receiver.AcceptMessage(msg, receiverCh)
		}

		requireConnRead(t, receiver, "hello")
		_, err = receiver.Read(make([]byte, 64))
		req.ErrorIs(err, io.EOF)

		// the stream is ended once
		req.NoError(sender.Close())
		for _, msg := range senderCh.take() {
			req.Equal(int32(edge.ContentTypeStateClosed), msg.ContentType)
		}
	})

	t.Run("Close", func(t *testing.T) {
		req := require.New(t)
		sender, senderCh, receiver, receiverCh := newEncryptedLegacyPair(t)

		_, err := sender.Write([]byte("hello"))
		req.NoError(err)
		req.NoError(sender.Close())

		msgs := senderCh.take()
		req.Len(msgs, 4, "expected the crypto header, the data, the final chunk and the StateClosed")
		req.Equal(int32(edge.ContentTypeStateClosed), msgs[3].ContentType)
		for _, msg := range msgs {
			receiver.AcceptMessage(msg, receiverCh)
		}

		requireConnRead(t, receiver, "hello")
		_, err = receiver.Read(make([]byte, 64))
		req.ErrorIs(err, io.EOF)
		req.True(receiver.IsClosed())
	})
}

// A router that drops the tail of a stream and ends it itself, with a FIN or a StateClosed, has
// no way to produce the final chunk. The peer reads what was let through and then an error where
// it used to read io.EOF.
func Test_LegacyConn_TruncatedEncryptedStream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ending func(connId uint32) *channel.Message
	}{
		{name: "FIN", ending: finMsg},
		{name: "StateClosed", ending: func(connId uint32) *channel.Message {
			return edge.NewStateClosedMsg(connId, "test")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := require.New(t)
			sender, senderCh, receiver, receiverCh := newEncryptedLegacyPair(t)

			_, err := sender.Write([]byte("pay 100"))
			req.NoError(err)
			_, err = sender.Write([]byte(" to nobody"))
			req.NoError(err)

			msgs := senderCh.take()
			req.Len(msgs, 3, "expected the crypto header and two data messages")
			receiver.AcceptMessage(msgs[0], receiverCh)
			receiver.AcceptMessage(msgs[1], receiverCh)
			receiver.AcceptMessage(tc.ending(receiver.Id()), receiverCh)

			requireConnRead(t, receiver, "pay 100")
			for i := 0; i < 2; i++ {
				_, err = receiver.Read(make([]byte, 64))
				req.ErrorIs(err, io.ErrUnexpectedEOF)
			}
		})
	}
}

// An xgress conn ends its encrypted stream with a final chunk when it half-closes or closes.
func Test_XgressConn_CloseSendsFinalChunk(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(conn *edgeConnXgress) error
	}{
		{name: "CloseWrite", close: (*edgeConnXgress).CloseWrite},
		{name: "Close", close: (*edgeConnXgress).Close},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := require.New(t)
			ch := newRecordingTestChannel()
			conn, _, _ := newXgressCloseTestConnOn(t, ch)

			key, err := secretstream.NewStreamKey()
			req.NoError(err)
			var header []byte
			conn.sender, header, err = secretstream.NewEncryptor(key)
			req.NoError(err)
			receiver, err := secretstream.NewDecryptor(key, header)
			req.NoError(err)

			_, err = conn.Write([]byte("hello"))
			req.NoError(err)
			req.NoError(tc.close(conn))
			_, err = conn.Write([]byte("more"))
			req.Error(err)

			var tags []byte
			var data []string
			for _, msg := range ch.take() {
				if msg.ContentType != edge.ContentTypeXgPayload {
					continue
				}
				payload, err := xgress.UnmarshallPayload(msg)
				req.NoError(err)
				if len(payload.Data) == 0 {
					continue
				}
				plain, tag, err := receiver.Pull(payload.Data)
				req.NoError(err)
				tags = append(tags, tag)
				data = append(data, string(plain))
			}
			req.Equal([]byte{secretstream.TagPush, secretstream.TagFinal}, tags)
			req.Equal([]string{"hello", ""}, data)
		})
	}
}
