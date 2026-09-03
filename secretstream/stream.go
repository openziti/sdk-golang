package secretstream

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	// nolint:staticcheck
	"golang.org/x/crypto/poly1305"
)

// public constants
const (
	TagMessage = 0
	TagPush    = 0x01
	TagRekey   = 0x02
	TagFinal   = TagPush | TagRekey

	StreamKeyBytes    = chacha20poly1305.KeySize
	StreamHeaderBytes = chacha20poly1305.NonceSizeX
	StreamABytes      = 16 + 1
)

const crypto_core_hchacha20_INPUTBYTES = 16

const crypto_secretstream_xchacha20poly1305_INONCEBYTES = 8
const crypto_secretstream_xchacha20poly1305_COUNTERBYTES = 4

var pad0 [16]byte

var errInvalidKey = errors.New("invalid key")
var errInvalidInput = errors.New("invalid input")
var errCryptoFailure = errors.New("crypto failed")

type streamState struct {
	k     [StreamKeyBytes]byte
	nonce [chacha20poly1305.NonceSize]byte
	pad   [8]byte
}

func (s *streamState) reset() {
	for i := range s.nonce {
		s.nonce[i] = 0
	}
	s.resetCounter()
}

// resetCounter sets the message counter back to one, leaving the inonce alone.
//
// Distinct from reset, which zeroes the whole nonce and is only correct during init, where
// the inonce is written afterwards. Rekeying derives a new inonce and must keep it.
func (s *streamState) resetCounter() {
	for i := 0; i < crypto_secretstream_xchacha20poly1305_COUNTERBYTES; i++ {
		s.nonce[i] = 0
	}
	s.nonce[0] = 1
}

// counterIsZero reports whether the message counter has wrapped back to zero.
func (s *streamState) counterIsZero() bool {
	var zero [crypto_secretstream_xchacha20poly1305_COUNTERBYTES]byte
	return subtle.ConstantTimeCompare(
		s.nonce[:crypto_secretstream_xchacha20poly1305_COUNTERBYTES], zero[:]) == 1
}

// rekey derives a new key and inonce from the current state and resets the counter.
//
// Both sides do this at the same points without announcing it, so an implementation that
// skips it desynchronizes from one that does not, and every later message fails to
// authenticate. See rekeyIfNeeded for when it fires.
func (s *streamState) rekey() error {
	var newKeyAndInonce [StreamKeyBytes + crypto_secretstream_xchacha20poly1305_INONCEBYTES]byte
	copy(newKeyAndInonce[:StreamKeyBytes], s.k[:])
	copy(newKeyAndInonce[StreamKeyBytes:],
		s.nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES:])

	chacha, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		return err
	}
	chacha.XORKeyStream(newKeyAndInonce[:], newKeyAndInonce[:])

	copy(s.k[:], newKeyAndInonce[:StreamKeyBytes])
	copy(s.nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES:],
		newKeyAndInonce[StreamKeyBytes:])
	memzero(newKeyAndInonce[:])

	s.resetCounter()
	return nil
}

// rekeyIfNeeded rekeys on either of the two triggers, having just sent or received a message
// tagged tag.
//
// The explicit trigger is a rekey tag, which TagFinal also carries. The implicit one is the
// counter wrapping after 2^32 messages on a stream, and it is the one that matters, because
// nothing opts into it and nothing on the wire marks it.
func (s *streamState) rekeyIfNeeded(tag byte) error {
	if tag&TagRekey != 0 || s.counterIsZero() {
		return s.rekey()
	}
	return nil
}

type Encryptor interface {
	Push(m []byte, tag byte) ([]byte, error)
}

type Decryptor interface {
	Pull(m []byte) ([]byte, byte, error)
}

type encryptor struct {
	streamState
}

type decryptor struct {
	streamState
}

func NewStreamKey() ([]byte, error) {
	k := make([]byte, chacha20poly1305.KeySize)
	_, err := rand.Read(k)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func NewEncryptor(key []byte) (Encryptor, []byte, error) {
	header := make([]byte, StreamHeaderBytes)
	if _, err := rand.Read(header); err != nil {
		return nil, nil, err
	}

	stream, err := newEncryptorWithHeader(key, header)
	if err != nil {
		return nil, nil, err
	}
	return stream, header, nil
}

// newEncryptorWithHeader initializes a send stream over a caller-supplied header.
//
// Unexported because a header must be unpredictable for the stream to be safe, which is why
// NewEncryptor generates its own. This exists so tests can pin one and get reproducible
// ciphertext.
func newEncryptorWithHeader(key, header []byte) (Encryptor, error) {
	if len(key) != StreamKeyBytes {
		return nil, errInvalidKey
	}
	if len(header) != StreamHeaderBytes {
		return nil, errInvalidInput
	}

	stream := &encryptor{}

	k, err := chacha20.HChaCha20(key, header[:crypto_core_hchacha20_INPUTBYTES])
	if err != nil {
		return nil, err
	}
	copy(stream.k[:], k)
	stream.reset()

	for i := range stream.pad {
		stream.pad[i] = 0
	}

	copy(stream.nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES:],
		header[crypto_core_hchacha20_INPUTBYTES:])

	return stream, nil
}

func (s *encryptor) Push(plain []byte, tag byte) ([]byte, error) {
	var err error

	//crypto_onetimeauth_poly1305_state poly1305_state;
	var poly *poly1305.MAC

	//unsigned char                     block[64U];
	var block [64]byte

	//unsigned char                     slen[8U];
	var slen [8]byte

	//unsigned char                    *c;
	//unsigned char                    *mac;
	//
	//if (outlen_p != NULL) {
	//*outlen_p = 0U;
	//}

	mlen := len(plain)
	//if (mlen > crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX) {
	//sodium_misuse();
	//}

	out := make([]byte, mlen+StreamABytes)

	chacha, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		return nil, err
	}
	//crypto_stream_chacha20_ietf(block, sizeof block, state->nonce, state->k);
	chacha.XORKeyStream(block[:], block[:])

	//crypto_onetimeauth_poly1305_init(&poly1305_state, block);
	var poly_init [32]byte
	copy(poly_init[:], block[:])
	poly = poly1305.New(&poly_init)

	// TODO add support for add data
	//sodium_memzero(block, sizeof block);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, ad, adlen);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, _pad0,
	//(0x10 - adlen) & 0xf);

	//memset(block, 0, sizeof block);
	//block[0] = tag;
	memzero(block[:])
	block[0] = tag

	//
	//crypto_stream_chacha20_ietf_xor_ic(block, block, sizeof block, state->nonce, 1U, state->k);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, block, sizeof block);
	//out[0] = block[0];
	chacha.XORKeyStream(block[:], block[:])
	_, _ = poly.Write(block[:])
	out[0] = block[0]

	//
	//c = out + (sizeof tag);
	c := out[1:]
	//crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, state->nonce, 2U, state->k);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, c, mlen);
	//crypto_onetimeauth_poly1305_update (&poly1305_state, _pad0, (0x10 - (sizeof block) + mlen) & 0xf);
	chacha.XORKeyStream(c, plain)
	_, _ = poly.Write(c[:mlen])
	padlen := (0x10 - len(block) + mlen) & 0xf
	_, _ = poly.Write(pad0[:padlen])

	//
	//STORE64_LE(slen, (uint64_t) adlen);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);
	binary.LittleEndian.PutUint64(slen[:], uint64(0))
	_, _ = poly.Write(slen[:])

	//STORE64_LE(slen, (sizeof block) + mlen);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);
	binary.LittleEndian.PutUint64(slen[:], uint64(len(block)+mlen))
	_, _ = poly.Write(slen[:])

	//
	//mac = c + mlen;
	//crypto_onetimeauth_poly1305_final(&poly1305_state, mac);
	mac := c[mlen:]
	copy(mac, poly.Sum(nil))
	//sodium_memzero(&poly1305_state, sizeof poly1305_state);
	//

	//XOR_BUF(STATE_INONCE(state), mac, crypto_secretstream_xchacha20poly1305_INONCEBYTES);
	//sodium_increment(STATE_COUNTER(state), crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
	xor_buf(s.nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES:], mac)
	buf_inc(s.nonce[:crypto_secretstream_xchacha20poly1305_COUNTERBYTES])

	if err = s.rekeyIfNeeded(tag); err != nil {
		return nil, err
	}

	//if (outlen_p != NULL) {
	//*outlen_p = crypto_secretstream_xchacha20poly1305_ABYTES + mlen;
	//}

	//return 0;
	return out, nil
}

func NewDecryptor(key, header []byte) (Decryptor, error) {
	// Both lengths are checked up front because the header arrives from the peer. A short
	// one used to panic on the slice below, and one of 16 to 23 bytes was worse: it built a
	// decryptor whose nonce was part zero, which fails later and somewhere else.
	if len(key) != StreamKeyBytes {
		return nil, errInvalidKey
	}
	if len(header) != StreamHeaderBytes {
		return nil, errInvalidInput
	}

	stream := &decryptor{}

	//crypto_core_hchacha20(state->k, in, k, NULL);
	k, err := chacha20.HChaCha20(key, header[:16])
	if err != nil {
		return nil, err
	}
	copy(stream.k[:], k)

	//_crypto_secretstream_xchacha20poly1305_counter_reset(state);
	stream.reset()

	//memcpy(STATE_INONCE(state), in + crypto_core_hchacha20_INPUTBYTES,
	//	crypto_secretstream_xchacha20poly1305_INONCEBYTES);
	copy(stream.nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES:],
		header[crypto_core_hchacha20_INPUTBYTES:])

	//memset(state->_pad, 0, sizeof state->_pad);
	copy(stream.pad[:], pad0[:])

	//fmt.Printf("decryptor: %+v\n", stream.streamState)

	return stream, nil
}

func (s *decryptor) Pull(in []byte) ([]byte, byte, error) {
	inlen := len(in)
	//crypto_onetimeauth_poly1305_state poly1305_state;

	//unsigned char                     block[64U];
	var block [64]byte

	//unsigned char                     slen[8U];
	var slen [8]byte

	//unsigned char                     mac[crypto_onetimeauth_poly1305_BYTES];
	//const unsigned char              *c;
	//const unsigned char              *stored_mac;
	//unsigned long long                mlen;
	//unsigned char                     tag;
	//
	//if (mlen_p != NULL) {
	//*mlen_p = 0U;
	//}
	//if (tag_p != NULL) {
	//*tag_p = 0xff;
	//}

	//if (inlen < crypto_secretstream_xchacha20poly1305_ABYTES) {
	//return -1;
	//}
	if inlen < StreamABytes {
		return nil, 0, errInvalidInput
	}
	//mlen = inlen - crypto_secretstream_xchacha20poly1305_ABYTES;
	mlen := inlen - StreamABytes

	//if (mlen > crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX) {
	//sodium_misuse();
	//}

	chacha, err := chacha20.NewUnauthenticatedCipher(s.k[:], s.nonce[:])
	if err != nil {
		return nil, 0, err
	}
	//crypto_stream_chacha20_ietf(block, sizeof block, state->nonce, state->k);
	chacha.XORKeyStream(block[:], block[:])

	//crypto_onetimeauth_poly1305_init(&poly1305_state, block);
	var poly_init [32]byte
	copy(poly_init[:], block[:])
	poly := poly1305.New(&poly_init)

	// TODO
	//sodium_memzero(block, sizeof block);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, ad, adlen);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, _pad0,
	//(0x10 - adlen) & 0xf);
	//

	//memset(block, 0, sizeof block);
	memzero(block[:])
	//block[0] = in[0];
	block[0] = in[0]

	//crypto_stream_chacha20_ietf_xor_ic(block, block, sizeof block, state->nonce, 1U, state->k);
	chacha.XORKeyStream(block[:], block[:])
	//tag = block[0];
	tag := block[0]
	//block[0] = in[0];
	block[0] = in[0]
	//crypto_onetimeauth_poly1305_update(&poly1305_state, block, sizeof block);
	if _, err = poly.Write(block[:]); err != nil {
		return nil, 0, err
	}

	//
	//c = in + (sizeof tag);
	c := in[1:]
	//crypto_onetimeauth_poly1305_update(&poly1305_state, c, mlen);
	if _, err = poly.Write(c[:mlen]); err != nil {
		return nil, 0, err
	}

	//crypto_onetimeauth_poly1305_update (&poly1305_state, _pad0, (0x10 - (sizeof block) + mlen) & 0xf);
	padlen := (0x10 - len(block) + mlen) & 0xf
	if _, err = poly.Write(pad0[:padlen]); err != nil {
		return nil, 0, err
	}

	//
	//STORE64_LE(slen, (uint64_t) adlen);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);
	binary.LittleEndian.PutUint64(slen[:], uint64(0))
	if _, err = poly.Write(slen[:]); err != nil {
		return nil, 0, err
	}

	//STORE64_LE(slen, (sizeof block) + mlen);
	//crypto_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);
	binary.LittleEndian.PutUint64(slen[:], uint64(len(block)+mlen))
	if _, err = poly.Write(slen[:]); err != nil {
		return nil, 0, err
	}

	//
	//crypto_onetimeauth_poly1305_final(&poly1305_state, mac);
	//sodium_memzero(&poly1305_state, sizeof poly1305_state);
	mac := poly.Sum(nil)
	//
	//stored_mac = c + mlen;
	stored_mac := c[mlen:]
	//if (sodium_memcmp(mac, stored_mac, sizeof mac) != 0) {
	//sodium_memzero(mac, sizeof mac);
	//return -1;
	//}
	if subtle.ConstantTimeCompare(mac, stored_mac) == 0 {
		return nil, 0, errCryptoFailure
	}
	//
	//crypto_stream_chacha20_ietf_xor_ic(m, c, mlen, state->nonce, 2U, state->k);
	m := make([]byte, mlen)
	chacha.XORKeyStream(m, c[:mlen])

	//XOR_BUF(STATE_INONCE(state), mac, crypto_secretstream_xchacha20poly1305_INONCEBYTES);
	//sodium_increment(STATE_COUNTER(state), crypto_secretstream_xchacha20poly1305_COUNTERBYTES);
	xor_buf(s.nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES:], mac)
	buf_inc(s.nonce[:crypto_secretstream_xchacha20poly1305_COUNTERBYTES])

	if err = s.rekeyIfNeeded(tag); err != nil {
		return nil, 0, err
	}

	//if (mlen_p != NULL) {
	//*mlen_p = mlen;
	//}
	//if (tag_p != NULL) {
	//*tag_p = tag;
	//}
	//return 0;
	return m, tag, nil
}

func memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func xor_buf(out, in []byte) {
	for i := range out {
		out[i] ^= in[i]
	}
}

func buf_inc(n []byte) {
	c := 1

	for i := range n {
		c += int(n[i])
		n[i] = byte(c)
		c >>= 8
	}
}
