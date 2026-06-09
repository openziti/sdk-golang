package edge

import (
	"io"
	"sync/atomic"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v5"
)

const (
	ChannelTypeControl string = "edge.control"
	ChannelTypeDefault string = "edge.default"
)

func NewBaseSdkChannel() *BaseSdkChannel {
	senderContext := channel.NewSenderContext()

	defaultMsgChan := make(chan channel.Sendable, 64)
	controlMsgChan := make(chan channel.Sendable, 4)
	retryMsgChan := make(chan channel.Sendable, 4)

	result := &BaseSdkChannel{
		SenderContext:  senderContext,
		defaultSender:  channel.NewSingleChSender(senderContext, defaultMsgChan),
		controlSender:  channel.NewSingleChSender(senderContext, controlMsgChan),
		controlMsgChan: controlMsgChan,
		defaultMsgChan: defaultMsgChan,
		retryMsgChan:   retryMsgChan,
	}
	return result
}

// SdkChannel provides access to an edge channel and its priority senders. The grouped
// (multi-underlay) implementation is BaseSdkChannel; the single-underlay fallback is
// SingleSdkChannel.
type SdkChannel interface {
	InitChannel(ch channel.Channel)
	GetChannel() channel.Channel
	GetDefaultSender() channel.Sender
	GetControlSender() channel.Sender
}

// BaseSdkChannel implements the channel/v5 Senders, MessageSourceProvider and
// UnderlayEventListener interfaces for a grouped edge channel, routing control
// messages onto the control underlay when one is present and onto the default
// underlay otherwise.
type BaseSdkChannel struct {
	channel.SenderContext
	ch            channel.Channel
	controlSender channel.Sender
	defaultSender channel.Sender

	controlChannelAvailable atomic.Bool
	controlMsgChan          chan channel.Sendable
	defaultMsgChan          chan channel.Sendable
	retryMsgChan            chan channel.Sendable
}

// InitChannel records the channel for later access. It is called from the bind handler,
// which runs before any underlay event, so the reference is safe to read afterward.
func (self *BaseSdkChannel) InitChannel(ch channel.Channel) {
	self.ch = ch
}

func (self *BaseSdkChannel) GetChannel() channel.Channel {
	return self.ch
}

func (self *BaseSdkChannel) GetDefaultSender() channel.Sender {
	return self.defaultSender
}

func (self *BaseSdkChannel) GetControlSender() channel.Sender {
	return self.controlSender
}

func (self *BaseSdkChannel) GetNextMsgDefault(notifier *channel.CloseNotifier) (channel.Sendable, error) {
	if self.controlChannelAvailable.Load() {
		select {
		case msg := <-self.defaultMsgChan:
			return msg, nil
		case msg := <-self.retryMsgChan:
			return msg, nil
		case <-self.GetCloseNotify():
			return nil, io.EOF
		case <-notifier.GetCloseNotify():
			return nil, io.EOF
		}
	} else {
		select {
		case msg := <-self.defaultMsgChan:
			return msg, nil
		case msg := <-self.controlMsgChan:
			return msg, nil
		case msg := <-self.retryMsgChan:
			return msg, nil
		case <-self.GetCloseNotify():
			return nil, io.EOF
		case <-notifier.GetCloseNotify():
			return nil, io.EOF
		}
	}
}

func (self *BaseSdkChannel) GetNextControlMsg(notifier *channel.CloseNotifier) (channel.Sendable, error) {
	select {
	case msg := <-self.controlMsgChan:
		return msg, nil
	case msg := <-self.retryMsgChan:
		return msg, nil
	case <-self.GetCloseNotify():
		return nil, io.EOF
	case <-notifier.GetCloseNotify():
		return nil, io.EOF
	}
}

// GetMessageSource implements channel.MessageSourceProvider, draining the control queue
// for the control underlay and the default queue for everything else.
func (self *BaseSdkChannel) GetMessageSource(underlayType string) channel.MessageSourceF {
	if underlayType == ChannelTypeControl {
		return self.GetNextControlMsg
	}
	return self.GetNextMsgDefault
}

// HandleTxFailed requeues a send that failed on an underlay, completing the channel/v5
// Senders interface.
func (self *BaseSdkChannel) HandleTxFailed(_ string, sendable channel.Sendable) bool {
	select {
	case self.retryMsgChan <- sendable:
		return true
	case self.defaultMsgChan <- sendable:
		return true
	default:
		return false
	}
}

// UnderlayAdded implements channel.UnderlayEventListener.
func (self *BaseSdkChannel) UnderlayAdded(ch channel.Channel, underlay channel.Underlay) {
	self.UpdateCtrlChannelAvailable(ch)
	pfxlog.Logger().
		WithField("id", ch.Label()).
		WithField("underlays", ch.GetUnderlayCountsByType()).
		WithField("underlayType", channel.GetUnderlayType(underlay)).
		WithField("controlAvailable", self.controlChannelAvailable.Load()).
		Info("underlay added")
}

// UnderlayRemoved implements channel.UnderlayEventListener.
func (self *BaseSdkChannel) UnderlayRemoved(ch channel.Channel, underlay channel.Underlay) {
	self.UpdateCtrlChannelAvailable(ch)
	pfxlog.Logger().
		WithField("id", ch.Label()).
		WithField("underlays", ch.GetUnderlayCountsByType()).
		WithField("underlayType", channel.GetUnderlayType(underlay)).
		Info("underlay closed")
}

func (self *BaseSdkChannel) UpdateCtrlChannelAvailable(ch channel.Channel) {
	self.controlChannelAvailable.Store(ch.GetUnderlayCountsByType()[ChannelTypeControl] > 0)
}

// NewDialSdkChannel creates the dial-side grouped edge channel. The hand-rolled dial,
// grouping and backoff machinery from v4 is replaced by a channel.BackoffDialPolicy plus
// declarative constraints; the default underlay keeps Min: 1 so losing it closes the
// channel rather than recovering from zero.
func NewDialSdkChannel(dialer channel.DialUnderlayFactory, maxDefaultChannels, maxControlChannel int) *DialSdkChannel {
	result := &DialSdkChannel{
		BaseSdkChannel: NewBaseSdkChannel(),
	}

	backoffConfig := channel.DefaultBackoffConfig
	backoffConfig.MinDialInterval = 250 * time.Millisecond
	result.dialPolicy = channel.NewBackoffDialPolicyWithConfig(dialer, backoffConfig)

	result.constraints = map[string]channel.UnderlayConstraint{
		ChannelTypeDefault: {Desired: maxDefaultChannels, Min: 1},
		ChannelTypeControl: {Desired: maxControlChannel, Min: 0},
	}

	return result
}

type DialSdkChannel struct {
	*BaseSdkChannel
	dialPolicy  channel.DialPolicy
	constraints map[string]channel.UnderlayConstraint
}

func (self *DialSdkChannel) GetDialPolicy() channel.DialPolicy {
	return self.dialPolicy
}

func (self *DialSdkChannel) GetConstraints() map[string]channel.UnderlayConstraint {
	return self.constraints
}

func NewSingleSdkChannel(ch channel.Channel) SdkChannel {
	return &SingleSdkChannel{
		ch: ch,
	}
}

type SingleSdkChannel struct {
	ch channel.Channel
}

func (self *SingleSdkChannel) InitChannel(ch channel.Channel) {
	self.ch = ch
}

func (self *SingleSdkChannel) GetChannel() channel.Channel {
	return self.ch
}

func (self *SingleSdkChannel) GetDefaultSender() channel.Sender {
	return self.ch
}

func (self *SingleSdkChannel) GetControlSender() channel.Sender {
	return self.ch
}
