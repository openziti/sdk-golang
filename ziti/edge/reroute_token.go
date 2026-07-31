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
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// RerouteTokenPurpose is the fixed purpose claim of a reroute token. Every handler that accepts a
// reroute token asserts this before reading other claims, so a token signed by the same cluster
// key for a different purpose (e.g. an API-session token) cannot be fed into a reroute validator.
const RerouteTokenPurpose = "ziti-sdk-reroute"

// RerouteTokenVersion is the current reroute-token schema version. An incompatible format change
// bumps this; capability negotiation then chooses between old and new validators so mixed
// deployments coexist during rollout.
const RerouteTokenVersion uint32 = 1

// TokenSide identifies which endpoint of a circuit a reroute token authorizes the bearer to take
// over. Numbering is pinned with the same fail-safe pattern as the wire enums: the zero value is
// unspecified and MUST never authorize a takeover.
type TokenSide int32

const (
	TokenSideUnspecified TokenSide = 0
	// TokenSideIngress authorizes dialer-side (ingress) reroute.
	TokenSideIngress TokenSide = 1
	// TokenSideEgress authorizes terminator-side (egress) reroute.
	TokenSideEgress TokenSide = 2
)

// RerouteClaims are the claims carried by a controller-signed reroute token. The token is signed
// (not encrypted): every claim is either something the SDK already knows about itself or is
// non-sensitive, so integrity is all that is required. Holders with the cluster verification key
// (routers, controllers, and the SDK) can read the claims after verifying the signature.
type RerouteClaims struct {
	jwt.RegisteredClaims
	// CircuitId is the circuit this token authorizes action on.
	CircuitId string `json:"circuitId"`
	// IdentityId is the identity that owns the circuit; the new ingress router matches it against
	// the authenticated edge-channel identity before acting.
	IdentityId string `json:"identityId"`
	// ServiceId is the circuit's service; it lets a router do a trusted dial-access fail-fast and
	// lets the SDK pick reroute candidates without storing the service id separately.
	ServiceId string `json:"serviceId"`
	// XgressId is the xgress address of the circuit endpoint this token authorizes taking over,
	// for the side named by Side: the ingress xgress id for an Ingress token, the egress xgress id
	// for an Egress token. It is fixed at circuit creation and preserved across every reroute, so
	// the new router pre-registers its forwarder at this (controller-signed, trusted) address
	// rather than allocating a new one.
	XgressId string `json:"xgressId"`
	// Iteration is the per-circuit monotonic counter the token is bound to. The token is valid
	// while it equals the circuit's current iteration; a successful takeover advances the circuit
	// iteration, which invalidates a captured token.
	Iteration uint64 `json:"iteration"`
	// OwnerControllerId is the controller that owns the circuit; it tells the new router which
	// controller to dispatch the takeover to.
	OwnerControllerId string `json:"ownerControllerId"`
	// Purpose distinguishes reroute tokens from other artifacts signed by the same key.
	Purpose string `json:"purpose"`
	// Version is the token schema version.
	Version uint32 `json:"version"`
	// Side is the endpoint the token authorizes taking over.
	Side TokenSide `json:"side"`
}

// Validate is invoked by jwt.ParseWithClaims. It asserts the universal reroute-token invariants
// (purpose and schema version) so every parse path rejects token-confusion and unknown-version
// tokens before a handler reads any other claim. Context-specific checks (side, iteration,
// identity match) remain the caller's responsibility.
func (c *RerouteClaims) Validate() error {
	if c.Purpose != RerouteTokenPurpose {
		return fmt.Errorf("unexpected reroute token purpose %q", c.Purpose)
	}
	if c.Version != RerouteTokenVersion {
		return fmt.Errorf("unsupported reroute token version %d", c.Version)
	}
	return nil
}

// ParseRerouteToken verifies a reroute token's signature with the supplied key function and
// returns its validated claims. keyFunc supplies the cluster verification key (routers use their
// RDM-distributed public keys, controllers use the cluster JWKS, the SDK uses the keys it holds).
func ParseRerouteToken(tokenString string, keyFunc jwt.Keyfunc) (*RerouteClaims, error) {
	claims := &RerouteClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid reroute token")
	}
	return claims, nil
}
