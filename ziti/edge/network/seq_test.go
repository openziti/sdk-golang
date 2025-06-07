package network

import (
	"fmt"
	"github.com/openziti/channel/v4"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
	"time"
)

func Test_SeqNormalReadDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
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
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
	start := time.Now()
	readQ.SetReadDeadline(start.Add(10 * time.Millisecond))

	req := require.New(t)

	data := make([]byte, 877)
	msg := edge.NewDataMsg(1, data)
	req.NoError(readQ.PutSequenced(msg))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(msg, val)
}

func Test_SeqNormalReadWithNoDeadline(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
	req := require.New(t)

	data := make([]byte, 877)
	msg := edge.NewDataMsg(1, data)
	req.NoError(readQ.PutSequenced(msg))

	val, err := readQ.GetNext()
	req.NoError(err)
	req.Equal(msg, val)
}

func Test_SeqReadWithInterrupt(t *testing.T) {
	closeNotify := make(chan struct{})
	defer close(closeNotify)

	readQ := NewNoopSequencer[*channel.Message](closeNotify, 4)
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

func Test_GetMaxMsgMux(t *testing.T) {
	maxId := (math.MaxUint32 / 2) - 1
	fmt.Printf("max id: %d\n", maxId)
}
