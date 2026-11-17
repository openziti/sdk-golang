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
	"testing"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/channel/v5"
	"github.com/openziti/sdk-golang/v2/secretstream/kx"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// A dial reply without the host's public key fails the dial to a service that requires encryption,
// whether the header is missing or empty.
func Test_ClientCrypto_ReplyWithoutHostKeyFailsDial(t *testing.T) {
	keyPair, err := kx.NewKeyPair()
	require.NoError(t, err)

	replies := map[string]func(*channel.Message){
		"missing key": func(*channel.Message) {},
		"empty key": func(reply *channel.Message) {
			reply.Headers[edge.PublicKeyHeader] = []byte{}
		},
	}

	for name, prepare := range replies {
		t.Run(name, func(t *testing.T) {
			req := require.New(t)
			reply := channel.NewMessage(edge.ContentTypeStateConnected, nil)
			reply.PutByteHeader(edge.CryptoMethodHeader, byte(edge.CryptoMethodLibsodium))
			prepare(reply)

			established := false
			err := establishClientCryptoFromReply(pfxlog.Logger().WithField("test", t.Name()), reply, keyPair,
				func(*kx.KeyPair, []byte, edge.CryptoMethod) error {
					established = true
					return nil
				})
			req.Error(err)
			req.False(established, "crypto was set up without a host key")
		})
	}
}

// A dial reply carrying the host's public key sets up crypto with that key.
func Test_ClientCrypto_ReplyWithHostKeyEstablishesCrypto(t *testing.T) {
	req := require.New(t)
	keyPair, err := kx.NewKeyPair()
	req.NoError(err)
	hostKeyPair, err := kx.NewKeyPair()
	req.NoError(err)

	reply := channel.NewMessage(edge.ContentTypeStateConnected, nil)
	reply.Headers[edge.PublicKeyHeader] = hostKeyPair.Public()
	reply.PutByteHeader(edge.CryptoMethodHeader, byte(edge.CryptoMethodLibsodium))

	var peerKey []byte
	err = establishClientCryptoFromReply(pfxlog.Logger().WithField("test", t.Name()), reply, keyPair,
		func(_ *kx.KeyPair, key []byte, _ edge.CryptoMethod) error {
			peerKey = key
			return nil
		})
	req.NoError(err)
	req.Equal(hostKeyPair.Public(), peerKey)
}

// A dial without the client's public key is refused by a host whose service requires encryption: the
// router is told the dial failed and the application never sees the conn.
func Test_HostConn_DialWithoutClientKeyIsRefusedWhenEncryptionRequired(t *testing.T) {
	dials := map[string]func(*channel.Message){
		"xgress missing key": func(*channel.Message) {},
		"xgress empty key": func(dial *channel.Message) {
			dial.Headers[edge.PublicKeyHeader] = []byte{}
		},
		"legacy missing key": func(dial *channel.Message) {
			dial.PutBoolHeader(edge.UseXgressToSdkHeader, false)
		},
	}

	for name, prepare := range dials {
		t.Run(name, func(t *testing.T) {
			req := require.New(t)
			host, ch, mux := newAcceptTestHost(t, false)
			keyPair, err := kx.NewKeyPair()
			req.NoError(err)
			host.crypto = true
			host.keyPair = keyPair

			dial := newXgressDialMsg(51)
			prepare(dial)

			requireReturnsWithin(t, 5*time.Second, "newChildConnection", func() {
				host.newChildConnection(dial, host.SdkChannel)
			})
			req.Contains(ch.sentTypes(), int32(edge.ContentTypeDialFailed))
			req.NotContains(ch.sentTypes(), int32(edge.ContentTypeDialSuccess))
			req.Empty(host.acceptC, "an unencrypted conn was handed to the application")
			requireMuxHasConn(t, mux, 51, false)
		})
	}
}

// A host whose service does not require encryption still accepts a dial that carries no client key.
func Test_HostConn_DialWithoutClientKeyIsAcceptedWhenEncryptionNotRequired(t *testing.T) {
	req := require.New(t)
	host, ch, mux := newAcceptTestHost(t, false)

	requireReturnsWithin(t, 5*time.Second, "newChildConnection", func() {
		host.newChildConnection(newXgressDialMsg(52), host.SdkChannel)
	})
	req.NotContains(ch.sentTypes(), int32(edge.ContentTypeDialFailed))
	req.Contains(ch.sentTypes(), int32(edge.ContentTypeDialSuccess))
	req.Len(host.acceptC, 1)
	requireMuxHasConn(t, mux, 52, true)
}
