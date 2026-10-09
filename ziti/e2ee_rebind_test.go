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

package ziti

import (
	"crypto/fips140"
	"testing"
	"time"

	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/sdk-golang/v2/secretstream/kx"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/openziti/sdk-golang/v2/ziti/edge/network"
	"github.com/stretchr/testify/require"
)

// rebindListener records CloseListeners calls. All other MultiListener methods come from the embedded
// (nil) interface and panic if called.
type rebindListener struct {
	network.MultiListener
	closed chan struct{}
}

func (l *rebindListener) CloseListeners() error {
	l.closed <- struct{}{}
	return nil
}

// newRebindManager returns a listener manager for an encrypted service that picked libsodium
// before the controller capabilities loaded.
func newRebindManager(t *testing.T, controllerFips bool) (*listenerManager, *rebindListener) {
	ctx := e2eeMethodContext(edge.CryptoMethodLibsodium, controllerFips)
	keyPair, err := kx.NewKeyPair()
	require.NoError(t, err)
	encrypted := true
	name := "rebind-test"
	listener := &rebindListener{closed: make(chan struct{}, 1)}
	mgr := &listenerManager{
		service:         &rest_model.ServiceDetail{Name: &name, EncryptionRequired: &encrypted},
		context:         ctx,
		options:         &edge.ListenOptions{CryptoMethod: edge.CryptoMethodLibsodium, KeyPair: keyPair},
		pendingListens:  map[string]uint64{},
		listener:        listener,
		e2eeProvisional: true,
	}
	return mgr, listener
}

func requireRebind(t *testing.T, l *rebindListener, expected bool) {
	t.Helper()
	wait := 200 * time.Millisecond
	if expected {
		wait = 5 * time.Second
	}
	select {
	case <-l.closed:
		require.True(t, expected, "listeners closed with no method change")
	case <-time.After(wait):
		require.False(t, expected, "listeners not closed after the method changed")
	}
}

func TestRecheckE2eeMethodCapabilitiesNotLoaded(t *testing.T) {
	req := require.New(t)
	mgr, l := newRebindManager(t, true)
	mgr.context.CtrlClt.capabilitiesLoaded.Store(false)

	mgr.recheckE2eeMethod()
	req.True(mgr.e2eeProvisional)
	req.Equal(edge.CryptoMethodLibsodium, mgr.options.CryptoMethod)
	requireRebind(t, l, false)
}

// TestRecheckE2eeMethodControllerFips verifies that a controller reporting FIPS_MODE after the listen
// switches the listener to tls, drops its libsodium key pair, and closes the binds once, so new binds
// carry tls.
func TestRecheckE2eeMethodControllerFips(t *testing.T) {
	req := require.New(t)
	mgr, l := newRebindManager(t, true)

	mgr.recheckE2eeMethod()
	req.False(mgr.e2eeProvisional)
	req.Equal(edge.CryptoMethodTLS, mgr.options.CryptoMethod)
	req.Nil(mgr.options.KeyPair, "a tls listener sends no libsodium key")
	requireRebind(t, l, true)

	mgr.recheckE2eeMethod()
	requireRebind(t, l, false)
}

func TestRecheckE2eeMethodUnchanged(t *testing.T) {
	req := require.New(t)
	if fips140.Enabled() {
		t.Skip("a FIPS process always picks tls")
	}
	mgr, l := newRebindManager(t, false)
	keyPair := mgr.options.KeyPair

	mgr.recheckE2eeMethod()
	req.False(mgr.e2eeProvisional)
	req.Equal(edge.CryptoMethodLibsodium, mgr.options.CryptoMethod)
	req.Same(keyPair, mgr.options.KeyPair)
	requireRebind(t, l, false)
}

// TestRecheckE2eeMethodWaitsForPendingListens verifies that the switch waits until no bind is pending,
// because binds in flight read the listen options.
func TestRecheckE2eeMethodWaitsForPendingListens(t *testing.T) {
	req := require.New(t)
	mgr, l := newRebindManager(t, true)
	mgr.pendingListens["router-1"] = 1

	mgr.recheckE2eeMethod()
	req.True(mgr.e2eeProvisional)
	req.Equal(edge.CryptoMethodLibsodium, mgr.options.CryptoMethod)
	requireRebind(t, l, false)

	delete(mgr.pendingListens, "router-1")
	mgr.recheckE2eeMethod()
	req.Equal(edge.CryptoMethodTLS, mgr.options.CryptoMethod)
	requireRebind(t, l, true)
}
