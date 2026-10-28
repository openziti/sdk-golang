// jwtchat-idp issues client-credentials JWTs for the jwtchat example and serves the JWKS that
// verifies them. It is a demonstration issuer only: clients and secrets are hard-coded and the
// signing key is regenerated on every start.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	issuer        = "http://localhost:9998"
	listenAddr    = ":9998"
	tokenLifetime = 30 * time.Minute

	// audience is the value the jwtchat ext-jwt-signer is created with (-a openziti).
	audience = "openziti"
)

// clients maps client ids to secrets. A client's id is its token subject, which the controller
// matches against an identity's external id.
var clients = map[string]string{
	"cid1": "cid1secret",
	"cid2": "cid2secret",
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	jwk := jose.JSONWebKey{Key: key, Algorithm: string(jose.RS256), Use: "sig"}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
	jwk.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		log.Fatal(err)
	}
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, jwks)
	})
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		handleToken(w, r, signer)
	})

	log.Printf("server listening on %s", issuer)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}

func handleToken(w http.ResponseWriter, r *http.Request, signer jose.Signer) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		writeError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	clientID, secret, ok := r.BasicAuth()
	if !ok {
		clientID, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	expected, known := clients[clientID]
	if !known || subtle.ConstantTimeCompare([]byte(secret), []byte(expected)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid_client")
		return
	}

	now := time.Now()
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:    issuer,
		Subject:   clientID,
		Audience:  jwt.Audience{clientID, audience},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(tokenLifetime)),
		ID:        rand.Text(),
	}).Serialize()
	if err != nil {
		log.Printf("signing token for %s: %v", clientID, err)
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(tokenLifetime.Seconds()),
	})
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
