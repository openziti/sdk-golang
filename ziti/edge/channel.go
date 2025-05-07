package edge

import (
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v4"
	"io"
	"sync/atomic"
	"time"
)

const (
	ChannelTypeControl string = "edge.control"
	ChannelTypeDefault string = "edge.default"
)

func NewBaseSdkChannel(underlay channel.Underlay) *BaseSdkChannel {
	senderContext := channel.NewSenderContext()

	defaultMsgChan := make(chan channel.Sendable, 64)
	controlMsgChan := make(chan channel.Sendable, 4)
	retryMsgChan := make(chan channel.Sendable, 4)

	result := &BaseSdkChannel{
		SenderContext:  senderContext,
		id:             underlay.ConnectionId(),
		defaultSender:  channel.NewSingleChSender(senderContext, defaultMsgChan),
		controlSender:  channel.NewSingleChSender(senderContext, controlMsgChan),
		controlMsgChan: controlMsgChan,
		defaultMsgChan: defaultMsgChan,
		retryMsgChan:   retryMsgChan,
	}
	return result
}

type BaseSdkChannel struct {
	id string
	ch channel.MultiChannel
	channel.SenderContext
	controlSender channel.Sender
	defaultSender channel.Sender

	controlChannelAvailable atomic.Bool
	controlMsgChan          chan channel.Sendable
	defaultMsgChan          chan channel.Sendable
	retryMsgChan            chan channel.Sendable
}

func (self *BaseSdkChannel) InitChannel(ch channel.MultiChannel) {
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

func (self *BaseSdkChannel) GetMessageSource(underlay channel.Underlay) channel.MessageSourceF {
	if channel.GetUnderlayType(underlay) == ChannelTypeControl {
		return self.GetNextControlMsg
	}
	return self.GetNextMsgDefault
}

func (self *BaseSdkChannel) HandleTxFailed(_ channel.Underlay, sendable channel.Sendable) bool {
	select {
	case self.retryMsgChan <- sendable:
		return true
	case self.defaultMsgChan <- sendable:
		return true
	default:
		return false
	}
}

func (self *BaseSdkChannel) HandleUnderlayAccepted(ch channel.MultiChannel, underlay channel.Underlay) {
	self.UpdateCtrlChannelAvailable(ch)
	pfxlog.Logger().
		WithField("id", ch.Label()).
		WithField("underlays", ch.GetUnderlayCountsByType()).
		WithField("underlayType", channel.GetUnderlayType(underlay)).
		WithField("controlAvailable", self.controlChannelAvailable.Load()).
		Info("underlay added")
}

func (self *BaseSdkChannel) UpdateCtrlChannelAvailable(ch channel.MultiChannel) {
	self.controlChannelAvailable.Store(ch.GetUnderlayCountsByType()[ChannelTypeControl] > 0)
}

func NewDialSdkChannel(dialer channel.DialUnderlayFactory, underlay channel.Underlay, maxDefaultChannels, maxControlChannel int) UnderlayHandlerSdkChannel {
	result := &DialSdkChannel{
		BaseSdkChannel: *NewBaseSdkChannel(underlay),
		dialer:         dialer,
	}

	result.constraints.AddConstraint(ChannelTypeDefault, maxDefaultChannels, 1)
	result.constraints.AddConstraint(ChannelTypeControl, maxControlChannel, 0)

	return result
}

type UnderlayHandlerSdkChannel interface {
	SdkChannel
	channel.UnderlayHandler
}

type SdkChannel interface {
	InitChannel(channel.MultiChannel)
	GetChannel() channel.Channel
	GetDefaultSender() channel.Sender
	GetControlSender() channel.Sender
}

type DialSdkChannel struct {
	BaseSdkChannel
	dialer      channel.DialUnderlayFactory
	constraints channel.UnderlayConstraints
}

func (self *DialSdkChannel) Start(channel channel.MultiChannel) {
	self.constraints.Apply(channel, self)
}

func (self *DialSdkChannel) HandleUnderlayClose(ch channel.MultiChannel, underlay channel.Underlay) {
	pfxlog.Logger().
		WithField("id", ch.Label()).
		WithField("underlays", ch.GetUnderlayCountsByType()).
		WithField("underlayType", channel.GetUnderlayType(underlay)).
		Info("underlay closed")
	self.UpdateCtrlChannelAvailable(ch)
	self.constraints.Apply(ch, self)
}

func (self *DialSdkChannel) DialFailed(_ channel.MultiChannel, _ string, attempt int) {
	delay := 2 * time.Duration(attempt) * time.Second
	if delay > time.Minute {
		delay = time.Minute
	}
	time.Sleep(delay)
}

func (self *DialSdkChannel) CreateGroupedUnderlay(groupId string, groupSecret []byte, underlayType string, timeout time.Duration) (channel.Underlay, error) {
	return self.dialer.CreateWithHeaders(timeout, map[int32][]byte{
		channel.TypeHeader:         []byte(underlayType),
		channel.ConnectionIdHeader: []byte(groupId),
		channel.GroupSecretHeader:  groupSecret,
		channel.IsGroupedHeader:    {1},
	})
}

func NewSingleSdkChannel(ch channel.Channel) SdkChannel {
	return &SingleSdkChannel{
		ch: ch,
	}
}

type SingleSdkChannel struct {
	ch channel.Channel
}

func (self *SingleSdkChannel) InitChannel(channel.MultiChannel) {
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
