package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_SignAndVerifyRsa(t *testing.T) {
	req := require.New(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	req.NoError(err)
	testKeyPair(t, key, key.Public())
}

func Test_SignAndVerifyEcdsa(t *testing.T) {
	req := require.New(t)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	req.NoError(err)
	testKeyPair(t, key, key.Public())
}

func testKeyPair(t *testing.T, privateKey interface{}, publicKey interface{}) {
	req := require.New(t)
	sig, err := AssertIdentityWithSecret(privateKey)
	req.NoError(err)

	verifier, err := GetVerifier(sig)
	req.NoError(err)
	req.True(verifier.Verify(publicKey))
}
