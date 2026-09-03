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

package xgress

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/openziti/channel/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validPacketPayload builds a minimal well-formed v1 packet payload, so the truncation
// cases below differ from a frame that is known to decode.
func validPacketPayload() []byte {
	circuitId := "circuit1"
	buf := []byte{
		VersionMask & (PayloadProtocolV1 << PayloadProtocolOffset),
		CircuitIdSizeMask & byte(len(circuitId)),
	}
	buf = append(buf, circuitId...)
	seq := make([]byte, binary.MaxVarintLen64)
	buf = append(buf, seq[:binary.PutUvarint(seq, 42)]...)
	return append(buf, 'b', 'o', 'd', 'y')
}

// validV2Datagram builds a well-formed V2 frame carrying no headers and no body. Bit 0 of the
// first magic byte is set, which is what routes a datagram to the frame reader.
func validV2Datagram() []byte {
	buf := make([]byte, v2DatagramPrefixLen)
	copy(buf[0:4], []byte{0x03, 0x06, 0x09, 0x0c})
	binary.LittleEndian.PutUint32(buf[4:8], 1)   // content type
	binary.LittleEndian.PutUint32(buf[8:12], 1)  // sequence
	binary.LittleEndian.PutUint32(buf[12:16], 0) // headers length
	binary.LittleEndian.PutUint32(buf[16:20], 0) // body length
	return buf
}

// Test_UnmarshallPacketPayloadV2LengthsMustMatch covers a V2 datagram whose declared header
// and body lengths do not account for the bytes present, including a pair that wraps a uint32
// when summed at that width. A datagram carries exactly one whole message, so the declared
// sizes must be rejected here rather than handed to the frame reader.
func Test_UnmarshallPacketPayloadV2LengthsMustMatch(t *testing.T) {
	for _, tc := range []struct {
		name       string
		headersLen uint32
		bodyLen    uint32
	}{
		{name: "sum wraps a uint32", headersLen: 0xFFFFFFFF, bodyLen: 1},
		{name: "sum wraps to small", headersLen: 0xFFFFFFF0, bodyLen: 0x20},
		{name: "declares more than present", headersLen: 64, bodyLen: 0},
		{name: "declares less than present", headersLen: 0, bodyLen: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := validV2Datagram()
			binary.LittleEndian.PutUint32(buf[12:16], tc.headersLen)
			binary.LittleEndian.PutUint32(buf[16:20], tc.bodyLen)
			if tc.name == "declares less than present" {
				buf = append(buf, 'x', 'y', 'z')
			}

			require.NotPanics(t, func() {
				_, err := UnmarshallPacketPayload(buf)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "declares")
			})
		})
	}
}

// v2DatagramWithHeaders builds a V2 frame carrying the given header block, with the outer
// lengths set to match the datagram exactly.
func v2DatagramWithHeaders(block []byte) []byte {
	buf := validV2Datagram()
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(block)))
	return append(buf, block...)
}

// v2Header encodes one header entry: key, declared value length, value. declaredLen is separate
// from the value so a test can declare a width the entry does not carry.
func v2Header(key uint32, declaredLen uint32, value []byte) []byte {
	entry := make([]byte, 8+len(value))
	binary.LittleEndian.PutUint32(entry[0:4], key)
	binary.LittleEndian.PutUint32(entry[4:8], declaredLen)
	copy(entry[8:], value)
	return entry
}

// Test_UnmarshallPacketPayloadV2HeaderLengths covers header entries whose declared value width
// does not fit the header block, including widths above MaxInt32 that narrow to a negative int.
// The producer must reject these itself: it runs ahead of the bind handler, so it cannot leave
// the guarantee to whichever frame reader is linked. Asserting on the producer's own message is
// what makes this meaningful on a 64-bit run, where a downstream reader would also error.
func Test_UnmarshallPacketPayloadV2HeaderLengths(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block []byte
	}{
		{name: "width above MaxInt32", block: v2Header(7, 0xFFFFFFFF, nil)},
		{name: "width at MaxInt32 boundary", block: v2Header(7, 0x80000000, nil)},
		{name: "width exceeds block", block: v2Header(7, 64, []byte("short"))},
		{name: "entry header truncated", block: []byte{1, 2, 3, 4, 5}},
		{name: "second entry overruns", block: append(v2Header(7, 2, []byte("ok")), v2Header(8, 0xFFFFFFF0, nil)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := UnmarshallPacketPayload(v2DatagramWithHeaders(tc.block))
				require.Error(t, err)
				assert.Contains(t, err.Error(), "v2 header at offset")
			})
		})
	}
}

// Test_UnmarshallPacketPayloadV2HeadersValid is the control: a well-formed header block still
// reaches the frame reader and decodes.
func Test_UnmarshallPacketPayloadV2HeadersValid(t *testing.T) {
	block := append(v2Header(7, 2, []byte("ab")), v2Header(8, 0, nil)...)
	msg, err := UnmarshallPacketPayload(v2DatagramWithHeaders(block))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, []byte("ab"), msg.Headers[7])
}

func Test_UnmarshallPacketPayloadValid(t *testing.T) {
	msg, err := UnmarshallPacketPayload(validPacketPayload())
	require.NoError(t, err)
	require.NotNil(t, msg)

	circuitId, ok := msg.GetStringHeader(HeaderKeyCircuitId)
	require.True(t, ok)
	assert.Equal(t, "circuit1", circuitId)

	seq, ok := msg.GetUint64Header(HeaderKeySequence)
	require.True(t, ok)
	assert.Equal(t, uint64(42), seq)
	assert.Equal(t, []byte("body"), msg.Body)
}

// Test_UnmarshallPacketPayloadTruncated feeds every prefix of a valid payload, plus the flag
// combinations whose fields are read from the tail. Each must return an error, never panic.
func Test_UnmarshallPacketPayloadTruncated(t *testing.T) {
	valid := validPacketPayload()

	t.Run("prefixes", func(t *testing.T) {
		for i := 0; i < len(valid); i++ {
			require.NotPanics(t, func() {
				_, _ = UnmarshallPacketPayload(valid[:i])
			}, "panicked on prefix of length %d", i)
		}
	})

	// rtt and heartbeat are read from the head and tail respectively, so a frame that
	// sets the flag without carrying the field is the interesting truncation.
	for _, tc := range []struct {
		name string
		flag byte
	}{
		{name: "rtt flag, no rtt", flag: RttFlagMask},
		{name: "heartbeat flag, no heartbeat", flag: HeartbeatFlagMask},
		{name: "headers flag, no headers", flag: HeadersFlagMask},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := []byte{(VersionMask & (PayloadProtocolV1 << PayloadProtocolOffset)) | tc.flag, 0}
			require.NotPanics(t, func() {
				_, err := UnmarshallPacketPayload(buf)
				assert.Error(t, err)
			})
		})
	}

	t.Run("circuit id longer than remaining", func(t *testing.T) {
		buf := []byte{VersionMask & (PayloadProtocolV1 << PayloadProtocolOffset), CircuitIdSizeMask}
		require.NotPanics(t, func() {
			_, err := UnmarshallPacketPayload(buf)
			assert.Error(t, err)
		})
	})

	t.Run("sequence overflows uint64", func(t *testing.T) {
		buf := []byte{VersionMask & (PayloadProtocolV1 << PayloadProtocolOffset), 0}
		// eleven continuation bytes: more than a uint64 can hold, so Uvarint reports overflow
		for i := 0; i < 11; i++ {
			buf = append(buf, 0xff)
		}
		require.NotPanics(t, func() {
			_, err := UnmarshallPacketPayload(buf)
			assert.Error(t, err)
		})
	})
}

// Test_UnmarshallPacketPayloadHeaderValueOverflow covers a header map entry whose declared
// value size exceeds MaxInt64, a width at which a conversion to int goes negative and a
// length check done in int would admit it. The declared size must be rejected as exceeding
// the bytes available. The corpus entry in testdata reaches the same code by another input.
func Test_UnmarshallPacketPayloadHeaderValueOverflow(t *testing.T) {
	uvarint := func(v uint64) []byte {
		buf := make([]byte, binary.MaxVarintLen64)
		return buf[:binary.PutUvarint(buf, v)]
	}

	buf := []byte{
		(VersionMask & (PayloadProtocolV1 << PayloadProtocolOffset)) | HeadersFlagMask,
		0, // circuit id size
	}
	buf = append(buf, uvarint(0)...)              // sequence
	buf = append(buf, uvarint(1)...)              // one header follows
	buf = append(buf, 7)                          // header key
	buf = append(buf, uvarint(math.MaxUint64)...) // declared value size, no value follows

	require.NotPanics(t, func() {
		_, err := UnmarshallPacketPayload(buf)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ran out of space reading header")
	})
}

// Test_UnmarshallPacketPayloadMagicClassifiesFirst covers datagrams that set bit 0 but are not V2
// frames. Length validation must not run on them: the frame reader classifies by magic and returns
// the typed errors that drive version negotiation, and a length complaint would mask them.
func Test_UnmarshallPacketPayloadMagicClassifiesFirst(t *testing.T) {
	t.Run("unrecognized magic yields a magic error", func(t *testing.T) {
		buf := make([]byte, 24)
		copy(buf[0:4], []byte{0x03, 0x06, 0x09, 0x99})
		// lengths deliberately inconsistent with the datagram, which previously took precedence
		binary.LittleEndian.PutUint32(buf[12:16], 99)

		_, err := UnmarshallPacketPayload(buf)
		require.Error(t, err)
		assert.ErrorIs(t, err, channel.BadMagicNumberError)
	})

	t.Run("version negotiation response is classified, not length checked", func(t *testing.T) {
		uv := new(bytes.Buffer)
		uv.Write([]byte{0x03, 0x06, 0x09, 0x0a}) // unknown-version magic
		for _, v := range []uint32{2, 1, 2} {    // two versions supported: 1 and 2
			require.NoError(t, binary.Write(uv, binary.LittleEndian, v))
		}

		_, err := UnmarshallPacketPayload(uv.Bytes())
		require.Error(t, err)
		version, ok := channel.GetRetryVersion(err)
		require.True(t, ok, "expected a retryable version, got %v", err)
		assert.Equal(t, uint32(2), version)
	})
}

// FuzzUnmarshallPacketPayload covers the class rather than any enumerated input. The decoder
// reads peer-supplied datagrams ahead of the bind handler on a datagram underlay, so any input
// at all must produce a message or an error, never a panic.
//
// Seeds cover both dispatch branches: the packet format, and the V2 frame format that bit 0
// delegates to a frame reader. The V2 branch needs an explicit seed because reaching it
// requires the exact four-byte magic, which mutation is very unlikely to discover.
//
// Failing inputs land in testdata/fuzz/FuzzUnmarshallPacketPayload and run as ordinary
// subtests from then on. Rename each from the hash Go assigns to a name describing the input,
// since that name is all the test output shows. Nothing else may live in that directory: every
// file in it is parsed as a corpus entry, so a README breaks the run, and a corpus file takes
// no comments because every line after the version header is parsed as a value.
func FuzzUnmarshallPacketPayload(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{VersionMask & (PayloadProtocolV1 << PayloadProtocolOffset)})
	f.Add(validPacketPayload())

	full := validPacketPayload()
	full[0] |= RttFlagMask | HeartbeatFlagMask | HeadersFlagMask
	f.Add(full)

	f.Add(validV2Datagram())
	f.Add(v2DatagramWithHeaders(v2Header(7, 2, []byte("ab"))))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := UnmarshallPacketPayload(data)
		if err == nil && msg == nil {
			t.Fatal("returned a nil message and a nil error")
		}
	})
}
