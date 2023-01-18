package network

import (
	"github.com/openziti/channel/v2"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_SeqNormalReadDeadline(t *testing.T) {
	readQ := NewNoopSequencer[*channel.Message](4)
	start := time.Now()
	readQ.SetReadDeadline(start.Add(10 * time.Millisecond))

	req := require.New(t)
	_, err := readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})

	first := time.Now()
	req.True(first.Sub(start) >= 10*time.Millisecond)

	_, err = readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})
	req.True(time.Since(first) < time.Millisecond)
}

func Test_SeqNormalReadWithDeadline(t *testing.T) {
	readQ := NewNoopSequencer[*channel.Message](4)
	start := time.Now()
	readQ.SetReadDeadline(start.Add(10 * time.Millisecond))

	req := require.New(t)

	data := make([]byte, 877)
	msg := edge.NewDataMsg(1, 1, data)
	req.NoError(readQ.PutSequenced(msg))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(msg, val)
}

func Test_SeqNormalReadWithNoDeadline(t *testing.T) {
	readQ := NewNoopSequencer[*channel.Message](4)
	req := require.New(t)

	data := make([]byte, 877)
	msg := edge.NewDataMsg(1, 1, data)
	req.NoError(readQ.PutSequenced(msg))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(msg, val)
}

func Test_SeqReadWithInterrupt(t *testing.T) {
	readQ := NewNoopSequencer[*channel.Message](4)
	start := time.Now()

	req := require.New(t)

	go func() {
		readQ.SetReadDeadline(start.Add(10 * time.Millisecond))
	}()

	_, err := readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})
	first := time.Now()
	req.True(first.Sub(start) >= 10*time.Millisecond)

	_, err = readQ.GetNext()
	req.NotNil(err)
	req.ErrorIs(err, &ReadTimout{})
	req.True(time.Since(first) < time.Millisecond)
}
