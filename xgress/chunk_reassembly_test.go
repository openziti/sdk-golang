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
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newChunkTestXgress builds an Xgress far enough to drive nextTxPayload directly. The peer
// is never read from; payloads are pushed into the link receive buffer by hand.
func newChunkTestXgress(t *testing.T) *Xgress {
	t.Helper()
	options := DefaultOptions()
	options.TxQueueSize = 4
	xg := NewXgress("circuit1", "ctrl", "test", nil, Initiator, options, nil)
	t.Cleanup(func() { close(xg.closeNotify) })
	return xg
}

// chunkPayload wraps data as a chunked payload. declaredTotal is encoded as the leading
// uvarint when withHeader is set, letting a test declare a total the data does not match.
func chunkPayload(seq int32, declaredTotal uint64, withHeader bool, data []byte) *Payload {
	body := data
	if withHeader {
		hdr := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(hdr, declaredTotal)
		body = append(hdr[:n:n], data...)
	}
	return &Payload{
		CircuitId: "circuit1",
		Flags:     setPayloadFlag(0, PayloadFlagChunk),
		Sequence:  seq,
		Data:      body,
	}
}

func pushPayload(t *testing.T, xg *Xgress, p *Payload) {
	t.Helper()
	require.True(t, xg.linkRxBuffer.ReceiveUnordered(xg, p, math.MaxUint32))
}

// Test_parseChunkedPayloadSize covers the bound at its edges. It exercises the guard directly
// rather than through reassembly, because a declared total just above the bound is a size Go
// will genuinely attempt: routing these through the allocation would mean that any regression in
// the guard is a multi-gigabyte allocation rather than a failed assertion.
func Test_parseChunkedPayloadSize(t *testing.T) {
	encode := func(v uint64) []byte {
		buf := make([]byte, binary.MaxVarintLen64)
		return buf[:binary.PutUvarint(buf, v)]
	}

	for _, tc := range []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "zero", data: encode(0)},
		{name: "small", data: encode(4096)},
		{name: "at the bound", data: encode(maxChunkedPayloadSize)},
		{name: "one past the bound", data: encode(maxChunkedPayloadSize + 1), wantErr: "exceeds the maximum"},
		{name: "above a uint32", data: encode(math.MaxUint32), wantErr: "exceeds the maximum"},
		{name: "widest uint64", data: encode(math.MaxUint64), wantErr: "exceeds the maximum"},
		{name: "empty", data: nil, wantErr: "truncated or overflows"},
		{name: "overflows a uint64", data: bytes.Repeat([]byte{0xff}, 11), wantErr: "truncated or overflows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			size, read, err := parseChunkedPayloadSize(tc.data)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Positive(t, read)
			assert.LessOrEqual(t, size, uint64(maxChunkedPayloadSize))
		})
	}
}

// Test_ChunkDeclaredSizeTooLarge covers an oversized total through reassembly. The value is one
// Go refuses to allocate outright, so a regression in the guard surfaces as an immediate panic
// rather than an allocation attempt; the boundary values live in Test_parseChunkedPayloadSize.
func Test_ChunkDeclaredSizeTooLarge(t *testing.T) {
	xg := newChunkTestXgress(t)
	pushPayload(t, xg, chunkPayload(0, math.MaxUint64, true, []byte("partial")))

	require.NotPanics(t, func() {
		_, _, err := xg.nextTxPayload(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds the maximum")
	})
}

// Test_ChunkSizeHeaderTruncated covers a leading uvarint that cannot be read, for which
// binary.Uvarint reports a non-positive count. The chunk must be rejected rather than the
// count being used as an offset.
func Test_ChunkSizeHeaderTruncated(t *testing.T) {
	// eleven continuation bytes overflow a uint64, so Uvarint reports a negative count
	overflowing := make([]byte, 11)
	for i := range overflowing {
		overflowing[i] = 0xff
	}

	xg := newChunkTestXgress(t)
	pushPayload(t, xg, chunkPayload(0, 0, false, overflowing))

	require.NotPanics(t, func() {
		_, _, err := xg.nextTxPayload(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "truncated or overflows")
	})
}

// Test_ChunkOverrunsDeclaredSize covers a peer sending more bytes than it declared. The chunk
// must be rejected: silently accepting it leaves the write offset past the declared total, and
// the payload can then never complete.
func Test_ChunkOverrunsDeclaredSize(t *testing.T) {
	xg := newChunkTestXgress(t)

	// declare 8 bytes total, then send 6 and 6
	pushPayload(t, xg, chunkPayload(0, 8, true, []byte("aaaaaa")))
	pushPayload(t, xg, chunkPayload(1, 0, false, []byte("bbbbbb")))

	require.NotPanics(t, func() {
		_, _, err := xg.nextTxPayload(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "overruns its declared size")
	})
}

// Test_ChunkReassemblyRoundTrip is the control: a well-formed two-chunk payload still
// reassembles to the original bytes.
func Test_ChunkReassemblyRoundTrip(t *testing.T) {
	xg := newChunkTestXgress(t)

	want := []byte("hello there, this is a chunked payload")
	split := 10
	pushPayload(t, xg, chunkPayload(0, uint64(len(want)), true, want[:split]))
	pushPayload(t, xg, chunkPayload(1, 0, false, want[split:]))

	data, _, err := xg.nextTxPayload(nil)
	require.NoError(t, err)
	assert.Equal(t, want, data)
}

// Test_ChunkDeclaredSizeDoesNotDriveAllocation covers the memory a receiver commits when a peer
// declares a large total and then sends very little. The reassembly buffer must grow with the
// bytes that arrive, so the declared value cannot be used to amplify a few bytes into a large
// allocation.
func Test_ChunkDeclaredSizeDoesNotDriveAllocation(t *testing.T) {
	xg := newChunkTestXgress(t)

	const declared = maxChunkedPayloadSize // the largest total that passes validation
	pushPayload(t, xg, chunkPayload(0, declared, true, []byte("six!!!")))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	// no second chunk follows, so this returns on the deadline with the payload incomplete
	_, _, _ = xg.nextTxPayload(closedChan())
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("declared %d bytes, sent 6, allocated %d", uint64(declared), allocated)
	// bounded by the pre-allocation rather than a fixed figure, so this keeps its meaning if
	// initialChunkBufferCap is retuned
	assert.Less(t, allocated, uint64(2*initialChunkBufferCap),
		"reassembly allocated %d bytes for a 6 byte chunk; the declared total must not size the buffer", allocated)
	assert.LessOrEqual(t, cap(xg.txChunkPayload.Data), initialChunkBufferCap)
}

// closedChan returns an already-closed channel, so a read that has nothing to return gives up
// immediately rather than blocking.
func closedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// Test_ChunkReassemblyManyChunks covers reassembly across more chunks than the initial buffer
// capacity accommodates, so the growth path is exercised rather than only the first allocation.
func Test_ChunkReassemblyManyChunks(t *testing.T) {
	xg := newChunkTestXgress(t)

	want := bytes.Repeat([]byte("abcdefgh"), initialChunkBufferCap/8+64)
	const chunkLen = 4096

	var seq int32
	for off := 0; off < len(want); off += chunkLen {
		end := min(off+chunkLen, len(want))
		if off == 0 {
			pushPayload(t, xg, chunkPayload(seq, uint64(len(want)), true, want[off:end]))
		} else {
			pushPayload(t, xg, chunkPayload(seq, 0, false, want[off:end]))
		}
		seq++
	}

	data, _, err := xg.nextTxPayload(nil)
	require.NoError(t, err)
	assert.Equal(t, len(want), len(data))
	assert.True(t, bytes.Equal(want, data), "reassembled payload does not match what was sent")
}
