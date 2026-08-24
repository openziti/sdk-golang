package kx

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

var seed = makeSeed()

func makeSeed() []byte {
	s := make([]byte, SeedBytes)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func seedIncrement(s []byte) []byte {
	r := make([]byte, len(s))
	c := uint16(1)

	for i := range s {
		c += uint16(s[i])
		r[i] = byte(c)
		c >>= 8
	}

	return r
}

func TestNewKeyPair(t *testing.T) {
	pk, _ := hex.DecodeString("0e0216223f147143d32615a91189c288c1728cba3cc5f9f621b1026e03d83129")
	sk, _ := hex.DecodeString("cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6")
	kp := &KeyPair{}
	copy(kp.pk[:], pk)
	copy(kp.sk[:], sk)

	type args struct {
		seed []byte
	}

	tests := []struct {
		name    string
		args    args
		want    *KeyPair
		wantErr bool
	}{
		{
			name:    "pre-seeded key",
			args:    args{seed: seed},
			want:    kp,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newKeyPairFromSeed(tt.args.seed)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKeyPair() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyExchange_Seeded(t *testing.T) {
	client_pair, err := newKeyPairFromSeed(seed)
	if err != nil {
		t.Errorf("failed to get client key pair")
		return
	}
	server_pair, err := newKeyPairFromSeed(seedIncrement(seed))

	if err != nil {
		t.Errorf("failed to get server key pair")
		return
	}

	clt_rx, _ := hex.DecodeString("749519c68059bce69f7cfcc7b387a3de1a1e8237d110991323bf62870115731a")
	clt_tx, _ := hex.DecodeString("62c8f4fa81800abd0577d99918d129b65deb789af8c8351f391feb0cbf238604")

	client_rx, client_tx, err := client_pair.ClientSessionKeys(server_pair.Public())
	if err != nil {
		t.Errorf("ClientSessionKeys: error = %v", err)
		return
	}

	if !bytes.Equal(clt_rx, client_rx) {
		t.Errorf("ClientSessionKeys(): RX got = %v, want %v", client_rx, clt_rx)
	}
	if !bytes.Equal(clt_tx, client_tx) {
		t.Errorf("ClientSessionKeys(): TX got = %v, want %v", client_tx, clt_tx)
	}

	server_rx, server_tx, err := server_pair.ServerSessionKeys(client_pair.Public())
	if err != nil {
		t.Errorf("ServerSessionKeys: error = %v", err)
		return
	}

	if !bytes.Equal(server_rx, client_tx) ||
		!bytes.Equal(server_tx, client_rx) {
		t.Errorf("ServersSessionKeys(): do not match client's got = %v, want %v", server_rx, clt_tx)
		t.Errorf("ServersSessionKeys(): do not match client's got = %v, want %v", server_tx, clt_rx)
		return
	}
}

func TestKeyExchange(t *testing.T) {
	client_pair, err := NewKeyPair()
	if err != nil {
		t.Errorf("failed to get client key pair")
		return
	}
	server_pair, err := NewKeyPair()

	if err != nil {
		t.Errorf("failed to get server key pair")
		return
	}

	client_rx, client_tx, err := client_pair.ClientSessionKeys(server_pair.Public())
	if err != nil {
		t.Errorf("ClientSessionKeys: error = %v", err)
		return
	}

	server_rx, server_tx, err := server_pair.ServerSessionKeys(client_pair.Public())
	if err != nil {
		t.Errorf("ServerSessionKeys: error = %v", err)
		return
	}

	if !bytes.Equal(server_rx, client_tx) {
		t.Errorf("ServersSessionKeys(): do not match client's got = %v, want %v", server_rx, client_tx)
		return
	}

	if !bytes.Equal(server_tx, client_rx) {
		t.Errorf("ServersSessionKeys(): do not match client's got = %v, want %v", server_tx, client_rx)
		return
	}

}
