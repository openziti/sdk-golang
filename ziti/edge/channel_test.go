package edge

import (
	"testing"

	"github.com/openziti/channel/v5"
	"github.com/stretchr/testify/require"
)

// pushes a message onto the given queue and returns the source's next message,
// asserting the source drained that queue.
func requireSourceDrains(t *testing.T, source channel.MessageSourceF, queue chan channel.Sendable, contentType int32) {
	t.Helper()
	req := require.New(t)
	msg := channel.NewMessage(contentType, nil)
	queue <- msg

	notifier := channel.NewCloseNotifier()
	got, err := source(notifier)
	req.NoError(err)
	req.Equal(msg, got)
}

func TestBaseSdkChannel_MessageSourceRouting(t *testing.T) {
	t.Run("control underlay drains the control queue", func(t *testing.T) {
		base := NewBaseSdkChannel()
		source := base.GetMessageSource(ChannelTypeControl)
		requireSourceDrains(t, source, base.controlMsgChan, 1)
	})

	t.Run("default underlay drains the default queue", func(t *testing.T) {
		base := NewBaseSdkChannel()
		source := base.GetMessageSource(ChannelTypeDefault)
		requireSourceDrains(t, source, base.defaultMsgChan, 1)
	})

	t.Run("unknown underlay type routes to the default source", func(t *testing.T) {
		base := NewBaseSdkChannel()
		source := base.GetMessageSource("something-else")
		requireSourceDrains(t, source, base.defaultMsgChan, 1)
	})
}

func TestBaseSdkChannel_ControlAvailableGating(t *testing.T) {
	req := require.New(t)

	// When no control underlay is present, the default source must also drain control
	// messages, so control traffic still goes out over the default underlay.
	base := NewBaseSdkChannel()
	req.False(base.controlChannelAvailable.Load())

	ctrlMsg := channel.NewMessage(1, nil)
	base.controlMsgChan <- ctrlMsg

	got, err := base.GetNextMsgDefault(channel.NewCloseNotifier())
	req.NoError(err)
	req.Equal(ctrlMsg, got)

	// When a control underlay is present, the default source must NOT drain the control
	// queue; control messages are reserved for the control source.
	base.controlChannelAvailable.Store(true)
	base.controlMsgChan <- channel.NewMessage(1, nil)

	dataMsg := channel.NewMessage(2, nil)
	base.defaultMsgChan <- dataMsg

	got, err = base.GetNextMsgDefault(channel.NewCloseNotifier())
	req.NoError(err)
	req.Equal(dataMsg, got, "default source should skip the control queue when a control underlay is present")
}

func TestBaseSdkChannel_HandleTxFailedRequeues(t *testing.T) {
	req := require.New(t)
	base := NewBaseSdkChannel()

	msg := channel.NewMessage(1, nil)
	req.True(base.HandleTxFailed("edge.default", msg))

	select {
	case got := <-base.retryMsgChan:
		req.Equal(msg, got)
	default:
		req.Fail("expected the failed message on the retry queue")
	}
}

func TestNewDialSdkChannel_Constraints(t *testing.T) {
	req := require.New(t)
	dialSdkChannel := NewDialSdkChannel(nil, 3, 2)

	constraints := dialSdkChannel.GetConstraints()
	// the default underlay keeps Min: 1, so losing the last one closes the channel
	req.Equal(channel.UnderlayConstraint{Desired: 3, Min: 1}, constraints[ChannelTypeDefault])
	// control underlays are optional and refill while the default underlay remains
	req.Equal(channel.UnderlayConstraint{Desired: 2, Min: 0}, constraints[ChannelTypeControl])

	req.NotNil(dialSdkChannel.GetDialPolicy())
}
