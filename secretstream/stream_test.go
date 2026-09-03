package secretstream

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	common_test(t, NewEncryptor, NewDecryptor)
}

func common_test(t *testing.T,
	makeEnc func([]byte) (Encryptor, []byte, error),
	makeDec func(k, h []byte) (Decryptor, error)) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}

	sender, hdr, err := makeEnc(key)
	if err != nil {
		t.Fatal(err)
	}

	plain_text_messages := [][]byte{
		[]byte("Hello world"),
		randomData(100),
		randomData(1000),
		randomData(10000),
		[]byte("This is good-bye!"),
	}

	// Tags per message, rather than derived from the index. A rekey has to be in here: it is
	// the one part of the format that changes state on both sides without anything on the
	// wire saying so, so when this helper drives the libsodium implementations it is the case
	// most worth covering. Messages after the rekey only decode if both sides did it
	// identically.
	tags := []byte{TagMessage, TagPush, TagRekey, TagMessage, TagPush}
	if len(tags) != len(plain_text_messages) {
		t.Fatalf("test setup: %d tags for %d messages", len(tags), len(plain_text_messages))
	}

	var coded_msgs [][]byte

	for i, m := range plain_text_messages {
		coded, err := sender.Push(m, tags[i])
		if err != nil {
			t.Error(err)
		}
		coded_msgs = append(coded_msgs, coded)
	}

	var decoded_msgs [][]byte
	receiver, err := makeDec(key, hdr)
	if err != nil {
		t.Fatal(err)
	}

	for i, m := range coded_msgs {
		decoded, tag, err := receiver.Pull(m)
		if err != nil {
			t.Error("decoding error", err)
		}
		if tag != tags[i] {
			t.Errorf("message %d: got tag %d, want %d", i, tag, tags[i])
		}
		decoded_msgs = append(decoded_msgs, decoded)
	}

	for i := range plain_text_messages {
		if !bytes.Equal(plain_text_messages[i], decoded_msgs[i]) {
			t.Error("failed to decode")
		}
	}
}

func randomData(c int) []byte {
	out := make([]byte, c)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}
	return out
}

// TestNewDecryptorRejectsBadLengths covers the header arriving from the peer. A header
// shorter than 16 bytes used to panic on a slice, and one of 16 to 23 bytes produced a
// decryptor whose nonce was partly zero, which failed later and somewhere else.
func TestNewDecryptorRejectsBadLengths(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}

	for _, headerLen := range []int{0, 15, 16, 23, 25} {
		dec, err := NewDecryptor(key, make([]byte, headerLen))
		if err == nil {
			t.Errorf("header of %d bytes should be rejected, got a decryptor", headerLen)
		}
		if dec != nil {
			t.Errorf("header of %d bytes should not yield a decryptor", headerLen)
		}
	}

	if _, err := NewDecryptor(key, make([]byte, StreamHeaderBytes)); err != nil {
		t.Errorf("a header of the right length should be accepted, got %v", err)
	}

	for _, keyLen := range []int{0, 31, 33} {
		if _, err := NewDecryptor(make([]byte, keyLen), make([]byte, StreamHeaderBytes)); err == nil {
			t.Errorf("key of %d bytes should be rejected", keyLen)
		}
	}
}

// TestExplicitRekeyRoundTrip covers the tagged trigger: a message tagged TagRekey rekeys both
// sides after it is processed, so the messages that follow only decrypt if both did it.
func TestExplicitRekeyRoundTrip(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	sender, hdr, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDecryptor(key, hdr)
	if err != nil {
		t.Fatal(err)
	}

	messages := []struct {
		plain []byte
		tag   byte
	}{
		{[]byte("before the rekey"), TagMessage},
		{[]byte("carries the rekey"), TagRekey},
		{[]byte("after the rekey"), TagMessage},
		{[]byte("and the one after that"), TagMessage},
	}

	for i, m := range messages {
		coded, err := sender.Push(m.plain, m.tag)
		if err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
		got, tag, err := receiver.Pull(coded)
		if err != nil {
			t.Fatalf("pull %d: %v", i, err)
		}
		if !bytes.Equal(got, m.plain) {
			t.Errorf("message %d: got %q, want %q", i, got, m.plain)
		}
		if tag != m.tag {
			t.Errorf("message %d: got tag %d, want %d", i, tag, m.tag)
		}
	}
}

// TestTagFinalRekeys covers TagFinal carrying TagRekey in its bits, so it triggers a rekey the
// same way. Reading the tag as an equality check rather than a mask would miss this.
func TestTagFinalRekeys(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	sender, hdr, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDecryptor(key, hdr)
	if err != nil {
		t.Fatal(err)
	}

	enc := sender.(*encryptor)
	before := enc.k

	coded, err := sender.Push([]byte("last one"), TagFinal)
	if err != nil {
		t.Fatal(err)
	}
	if _, tag, err := receiver.Pull(coded); err != nil || tag != TagFinal {
		t.Fatalf("pull: err=%v tag=%d", err, tag)
	}

	if enc.k == before {
		t.Error("TagFinal should have rekeyed the sender")
	}
	if enc.k != receiver.(*decryptor).k {
		t.Error("sender and receiver keys should agree after a rekey")
	}
}

// TestCounterWrapRekeys covers the implicit trigger, which is the one that matters: nothing
// opts into it and nothing on the wire marks it. Reaching 2^32 messages honestly is not
// feasible, so the counter is wound to its last value and one message is sent across the wrap.
func TestCounterWrapRekeys(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	sender, hdr, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDecryptor(key, hdr)
	if err != nil {
		t.Fatal(err)
	}

	enc := sender.(*encryptor)
	dec := receiver.(*decryptor)
	for i := 0; i < crypto_secretstream_xchacha20poly1305_COUNTERBYTES; i++ {
		enc.nonce[i] = 0xff
		dec.nonce[i] = 0xff
	}
	keyBefore := enc.k

	// This message pushes the counter over, so both sides rekey after handling it.
	coded, err := sender.Push([]byte("the one that wraps"), TagMessage)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := receiver.Pull(coded)
	if err != nil {
		t.Fatalf("the wrapping message should still decrypt: %v", err)
	}
	if !bytes.Equal(got, []byte("the one that wraps")) {
		t.Errorf("got %q", got)
	}

	if enc.k == keyBefore {
		t.Fatal("the counter wrap should have rekeyed")
	}
	if enc.k != dec.k {
		t.Fatal("sender and receiver keys should agree after a wrap rekey")
	}
	assertCounterIsOne(t, &enc.streamState, "after a wrap rekey")
	assertCounterIsOne(t, &dec.streamState, "after a wrap rekey")

	// And the stream keeps working on the far side of the wrap.
	coded, err = sender.Push([]byte("after the wrap"), TagMessage)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err = receiver.Pull(coded); err != nil {
		t.Fatalf("message after the wrap: %v", err)
	}
	if !bytes.Equal(got, []byte("after the wrap")) {
		t.Errorf("after the wrap: got %q", got)
	}
}

// TestRekeyPreservesInonce guards the difference between resetting the counter and zeroing the
// whole nonce. Rekey derives a new inonce and must keep it; using the init-time reset here
// would silently discard it and desynchronize from libsodium.
func TestRekeyPreservesInonce(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	sender, _, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	enc := sender.(*encryptor)
	if _, err := sender.Push([]byte("prime the inonce"), TagMessage); err != nil {
		t.Fatal(err)
	}
	if err := enc.rekey(); err != nil {
		t.Fatal(err)
	}

	var zero [crypto_secretstream_xchacha20poly1305_INONCEBYTES]byte
	if bytes.Equal(enc.nonce[crypto_secretstream_xchacha20poly1305_COUNTERBYTES:], zero[:]) {
		t.Error("rekey should derive a new inonce, not zero it")
	}
	assertCounterIsOne(t, &enc.streamState, "after an explicit rekey")
}

// TestKnownAnswer pins the wire format against fixed inputs and pinned ciphertext.
//
// The round-trip tests are self-consistent: they encrypt and decrypt with the same code, so a
// change to framing, nonce advance or rekey derivation keeps them green while real peers
// break. These vectors are decrypted, not re-encrypted, so they fail if the format moves.
//
// Four messages, deliberately: the first pins header derivation, the second pins that the
// nonce advanced, and the last two straddle a rekey so its derivation is pinned too. Produced
// by this implementation and cross-checked against libsodium through the compat_test suite.
func TestKnownAnswer(t *testing.T) {
	key := mustHex(t, "8f4b1e0c2a9d7635e1c84f02b7a396d5081fae6c34b920d7e5a1c86f430b29de")
	header := mustHex(t, "3a7c11e95d20b48f6c03a91e77d5842b0fe6c39a15d072b8")

	vectors := []struct {
		ciphertext string
		plain      string
		tag        byte
	}{
		{"b2a21c7ebb087e6a74245a355b8c73e0ac17a2a29b85", "first", TagMessage},
		{"e5c08256e919ab5e1498c5de3a1aaa6813b064d85f2e26", "second", TagMessage},
		{"8f2312647fef7ace4a18dd951356abd8fab2344e43d4c765347314", "rekey here", TagRekey},
		{
			"025208e97f47dd9ab8b8456ac0ebc0aafe5855b0b09dda43494cfe89cf546772",
			"after the rekey",
			TagMessage,
		},
	}

	receiver, err := NewDecryptor(key, header)
	if err != nil {
		t.Fatal(err)
	}

	for i, v := range vectors {
		got, tag, err := receiver.Pull(mustHex(t, v.ciphertext))
		if err != nil {
			t.Fatalf("vector %d (%q): %v", i, v.plain, err)
		}
		if string(got) != v.plain {
			t.Errorf("vector %d: got %q, want %q", i, got, v.plain)
		}
		if tag != v.tag {
			t.Errorf("vector %d: got tag %d, want %d", i, tag, v.tag)
		}
	}

	// And the same vectors are what this implementation still produces.
	sender, err := newEncryptorWithHeader(key, header)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range vectors {
		coded, err := sender.Push([]byte(v.plain), v.tag)
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		if hex.EncodeToString(coded) != v.ciphertext {
			t.Errorf("vector %d: got %s, want %s", i, hex.EncodeToString(coded), v.ciphertext)
		}
	}
}

// TestPullRejectsCorruptInput covers the error paths, including that a failed pull leaves the
// stream where it was. A pull that advanced the nonce on failure would turn one bad message
// into a dead stream.
func TestPullRejectsCorruptInput(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}

	newStream := func(t *testing.T) (Encryptor, Decryptor) {
		t.Helper()
		sender, hdr, err := NewEncryptor(key)
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := NewDecryptor(key, hdr)
		if err != nil {
			t.Fatal(err)
		}
		return sender, receiver
	}

	corruptions := []struct {
		name    string
		corrupt func(coded []byte) []byte
	}{
		{"short input", func(c []byte) []byte { return c[:StreamABytes-1] }},
		{"empty input", func(c []byte) []byte { return nil }},
		{"flipped tag bit", func(c []byte) []byte { c[0] ^= 0x01; return c }},
		{"flipped body bit", func(c []byte) []byte { c[1] ^= 0x01; return c }},
		{"flipped mac bit", func(c []byte) []byte { c[len(c)-1] ^= 0x01; return c }},
	}

	for _, tc := range corruptions {
		t.Run(tc.name, func(t *testing.T) {
			sender, receiver := newStream(t)

			coded, err := sender.Push([]byte("a message worth reading"), TagMessage)
			if err != nil {
				t.Fatal(err)
			}
			corrupted := tc.corrupt(append([]byte(nil), coded...))

			if _, _, err := receiver.Pull(corrupted); err == nil {
				t.Fatal("corrupted input should not decrypt")
			}

			// The stream must be undisturbed: the original message still reads.
			got, _, err := receiver.Pull(coded)
			if err != nil {
				t.Fatalf("a failed pull should not advance the stream: %v", err)
			}
			if string(got) != "a message worth reading" {
				t.Errorf("got %q", got)
			}
		})
	}
}

// TestPullRejectsWrongKey covers a decryptor built with a key the sender never used.
func TestPullRejectsWrongKey(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}

	sender, hdr, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDecryptor(other, hdr)
	if err != nil {
		t.Fatal(err)
	}

	coded, err := sender.Push([]byte("not for you"), TagMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.Pull(coded); err == nil {
		t.Error("a stream should not decrypt under the wrong key")
	}
}

// TestPullRejectsOutOfOrder covers delivery out of order, which the nonce chain makes
// undecryptable by construction.
func TestPullRejectsOutOfOrder(t *testing.T) {
	key, err := NewStreamKey()
	if err != nil {
		t.Fatal(err)
	}
	sender, hdr, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewDecryptor(key, hdr)
	if err != nil {
		t.Fatal(err)
	}

	first, err := sender.Push([]byte("first"), TagMessage)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sender.Push([]byte("second"), TagMessage)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := receiver.Pull(second); err == nil {
		t.Error("the second message should not decrypt before the first")
	}
	if _, _, err := receiver.Pull(first); err != nil {
		t.Errorf("the first message should still decrypt: %v", err)
	}
}

// assertCounterIsOne checks the whole counter, not just its low byte.
//
// Worth being exact about. A resetCounter that left the counter at zero would make
// counterIsZero true and rekey on every subsequent message, and a Go-to-Go round trip would
// not notice because both ends would do it identically. Only a peer that gets this right would
// see the difference, which is the failure this whole change is about.
func assertCounterIsOne(t *testing.T, s *streamState, when string) {
	t.Helper()
	want := [crypto_secretstream_xchacha20poly1305_COUNTERBYTES]byte{1}
	got := s.nonce[:crypto_secretstream_xchacha20poly1305_COUNTERBYTES]
	if !bytes.Equal(got, want[:]) {
		t.Errorf("counter %s should be %v, got %v", when, want, got)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// BenchmarkPush and BenchmarkPull record the cost of the hot path, including allocations.
//
// Both allocate a payload-sized buffer per call. Whether that is worth changing depends on how
// the caller uses the result, so these exist to make the cost visible before anyone decides.
func BenchmarkPush(b *testing.B) {
	for _, size := range []int{64, 1024, 16 * 1024, 1024 * 1024} {
		b.Run(sizeName(size), func(b *testing.B) {
			key, err := NewStreamKey()
			if err != nil {
				b.Fatal(err)
			}
			sender, _, err := NewEncryptor(key)
			if err != nil {
				b.Fatal(err)
			}
			payload := randomData(size)

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := sender.Push(payload, TagMessage); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPull(b *testing.B) {
	for _, size := range []int{64, 1024, 16 * 1024, 1024 * 1024} {
		b.Run(sizeName(size), func(b *testing.B) {
			key, err := NewStreamKey()
			if err != nil {
				b.Fatal(err)
			}
			payload := randomData(size)

			// Pull advances the stream, so a message can only be pulled once and every
			// iteration needs its own. Preparing all b.N of them up front would hold
			// O(b.N * size): at a megabyte a message, calibration picks a b.N that turns
			// this into hundreds of megabytes, so the benchmark ends up measuring memory
			// pressure rather than Pull. Refill in bounded batches with the timer stopped.
			const batchBytes = 8 << 20
			batch := batchBytes / (size + StreamABytes)
			if batch < 1 {
				batch = 1
			}

			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()

			for done := 0; done < b.N; {
				b.StopTimer()
				n := batch
				if remaining := b.N - done; remaining < n {
					n = remaining
				}

				// A fresh stream per batch, since the previous one was consumed.
				sender, hdr, err := NewEncryptor(key)
				if err != nil {
					b.Fatal(err)
				}
				coded := make([][]byte, n)
				for i := range coded {
					if coded[i], err = sender.Push(payload, TagMessage); err != nil {
						b.Fatal(err)
					}
				}
				receiver, err := NewDecryptor(key, hdr)
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()

				for _, c := range coded {
					if _, _, err := receiver.Pull(c); err != nil {
						b.Fatal(err)
					}
				}
				done += n
			}
		})
	}
}

func sizeName(size int) string {
	switch {
	case size >= 1024*1024:
		return fmt.Sprintf("%dMiB", size/(1024*1024))
	case size >= 1024:
		return fmt.Sprintf("%dKiB", size/1024)
	default:
		return fmt.Sprintf("%dB", size)
	}
}
