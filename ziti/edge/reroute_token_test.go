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

package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func signRerouteToken(t *testing.T, key *ecdsa.PrivateKey, claims *RerouteClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign reroute token: %v", err)
	}
	return signed
}

func validClaims() *RerouteClaims {
	return &RerouteClaims{
		CircuitId:         "circuit-1",
		IdentityId:        "identity-1",
		ServiceId:         "service-1",
		XgressId:          "xgress-1",
		Iteration:         3,
		OwnerControllerId: "ctrl-1",
		Purpose:           RerouteTokenPurpose,
		Version:           RerouteTokenVersion,
		Side:              TokenSideIngress,
	}
}

func TestRerouteTokenRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyFunc := func(*jwt.Token) (any, error) { return &key.PublicKey, nil }

	signed := signRerouteToken(t, key, validClaims())

	claims, err := ParseRerouteToken(signed, keyFunc)
	if err != nil {
		t.Fatalf("expected valid token to parse, got: %v", err)
	}
	if claims.CircuitId != "circuit-1" || claims.ServiceId != "service-1" || claims.Iteration != 3 {
		t.Fatalf("claims did not round-trip: %+v", claims)
	}
	if claims.XgressId != "xgress-1" {
		t.Fatalf("xgress id did not round-trip: %q", claims.XgressId)
	}
	if claims.Side != TokenSideIngress {
		t.Fatalf("expected side Ingress, got %d", claims.Side)
	}
}

func TestRerouteTokenRejectsWrongPurpose(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyFunc := func(*jwt.Token) (any, error) { return &key.PublicKey, nil }

	claims := validClaims()
	claims.Purpose = "some-other-purpose"
	signed := signRerouteToken(t, key, claims)

	if _, err := ParseRerouteToken(signed, keyFunc); err == nil {
		t.Fatal("expected a token with the wrong purpose to be rejected")
	}
}

func TestRerouteTokenRejectsUnknownVersion(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyFunc := func(*jwt.Token) (any, error) { return &key.PublicKey, nil }

	claims := validClaims()
	claims.Version = RerouteTokenVersion + 1
	signed := signRerouteToken(t, key, claims)

	if _, err := ParseRerouteToken(signed, keyFunc); err == nil {
		t.Fatal("expected a token with an unknown version to be rejected")
	}
}

func TestRerouteTokenRejectsWrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyFunc := func(*jwt.Token) (any, error) { return &other.PublicKey, nil }

	signed := signRerouteToken(t, key, validClaims())

	if _, err := ParseRerouteToken(signed, keyFunc); err == nil {
		t.Fatal("expected a token verified against the wrong key to be rejected")
	}
}
