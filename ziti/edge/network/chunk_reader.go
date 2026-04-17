/*
	Copyright 2019 NetFoundry Inc.

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

package network

import (
	"encoding/binary"
	"io"
	"sync/atomic"

	"github.com/openziti/sdk-golang/edgexg"
	"github.com/openziti/sdk-golang/xgress"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/secretstream"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// chunkSource pulls the next raw chunk from an underlying transport. It returns
// the chunk bytes, the edge-layer flags (FIN, MULTIPART_MSG, STREAM, MULTIPART),
// and an error. io.EOF or ErrClosed indicate end-of-stream.
//
// Each transport implements this differently:
//   - legacy mode: pulls the next ContentTypeData message off the readQ
//   - xgress mode: pulls the next payload off the ReadAdapter
type chunkSource func() (data []byte, flags uint32, err error)

// edgeChunkReader presents an io.Reader interface over a chunkSource. It owns
// the cross-Read state that makes the edge read pipeline non-trivial:
//
//   - the "first chunk is the secretstream header" handshake
//   - per-chunk decryption once the header has been consumed
//   - splitting of multipart (length-prefixed) chunks
//   - buffering chunks or part-chunks that don't fit in the caller's buffer
//   - tracking readFIN so further reads return io.EOF
//
// edgeChunkReader is not safe for concurrent Read calls (matching net.Conn
// semantics). MarkFIN is safe to call from any goroutine.
type edgeChunkReader struct {
	source chunkSource

	// rxKey is the raw session key pending secretstream initialization.
	// It is consumed on the first chunk and replaced by receiver.
	rxKey    []byte
	receiver secretstream.Decryptor

	// inBuffer holds data that was decoded but didn't fit in the caller's
	// p slice. Subsequent Read calls drain this before pulling new chunks.
	inBuffer [][]byte

	readFIN atomic.Bool

	// logger is recomputed per Read call, so conns can include dynamic context
	// (e.g. circuitId, marker) without the reader knowing what those are.
	logger func() *logrus.Entry
}

// newEdgeChunkReader constructs a reader over the given source.
func newEdgeChunkReader(source chunkSource, logger func() *logrus.Entry) *edgeChunkReader {
	return &edgeChunkReader{
		source: source,
		logger: logger,
	}
}

// SetRxKey installs the session key for secretstream. The first chunk read
// after this call must be the secretstream header. Once the header is
// consumed, the key is cleared and subsequent chunks are decrypted.
func (r *edgeChunkReader) SetRxKey(key []byte) {
	r.rxKey = key
}

// MarkFIN forces the reader into end-of-stream. Subsequent Reads return
// io.EOF once buffered data is drained.
func (r *edgeChunkReader) MarkFIN() {
	r.readFIN.Store(true)
}

// ReadFIN reports whether the reader has seen or been forced to FIN.
func (r *edgeChunkReader) ReadFIN() bool {
	return r.readFIN.Load()
}

// IsEncrypted reports whether the reader is either waiting for the secretstream
// header (key set but no receiver yet) or actively decrypting (receiver set).
func (r *edgeChunkReader) IsEncrypted() bool {
	return r.rxKey != nil || r.receiver != nil
}

// Read fills p with decoded, decrypted data from the source. It pulls new
// chunks only when its internal buffer is empty. Each Read returns at most
// one chunk's worth of data, matching the existing doRead contract.
func (r *edgeChunkReader) Read(p []byte) (int, error) {
	log := r.logger()

	// Fast path: previously-buffered data.
	if len(r.inBuffer) > 0 {
		return r.drainBuffer(p), nil
	}

	for {
		if r.readFIN.Load() {
			log.Trace("readFIN true, returning EOF")
			return 0, io.EOF
		}

		data, flags, err := r.source()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, ErrClosed) {
				log.Debug("read exhausted, marking readFIN")
				r.readFIN.Store(true)
				return 0, io.EOF
			}
			return 0, err
		}

		if flags&edge.FIN != 0 {
			log.Trace("got fin chunk, marking readFIN")
			r.readFIN.Store(true)
		}

		if len(data) == 0 && r.readFIN.Load() {
			return 0, io.EOF
		}

		// The first chunk on an encrypted stream carries the secretstream header.
		// Consume it, initialize the decryptor, and loop to read the next chunk.
		if r.rxKey != nil {
			if len(data) != secretstream.StreamHeaderBytes {
				return 0, errors.Errorf("failed to receive crypto header bytes: read[%d]", len(data))
			}
			r.receiver, err = secretstream.NewDecryptor(r.rxKey, data)
			if err != nil {
				return 0, errors.Wrap(err, "failed to init decryptor")
			}
			r.rxKey = nil
			continue
		}

		if r.receiver != nil {
			data, _, err = r.receiver.Pull(data)
			if err != nil {
				log.Errorf("crypto failed on chunk of size=%d err=(%v)", len(data), err)
				return 0, err
			}
		}

		multipart := flags&edge.MULTIPART_MSG != 0
		n := r.deliver(p, data, multipart)
		log.Tracef("%d chunks in incoming buffer", len(r.inBuffer))
		log.Debugf("read %d bytes", n)
		return n, nil
	}
}

// drainBuffer copies from the head of inBuffer into p and updates the buffer.
func (r *edgeChunkReader) drainBuffer(p []byte) int {
	first := r.inBuffer[0]
	n := copy(p, first)
	first = first[n:]
	if len(first) == 0 {
		r.inBuffer = r.inBuffer[1:]
	} else {
		r.inBuffer[0] = first
	}
	return n
}

// deliver copies the head of the decoded data into p, splitting multipart
// chunks on length prefixes. Anything that doesn't fit is queued in inBuffer.
func (r *edgeChunkReader) deliver(p, data []byte, multipart bool) int {
	if multipart && len(data) > 0 {
		parts := splitMultipart(data)
		n := copy(p, parts[0])
		parts[0] = parts[0][n:]
		if len(parts[0]) == 0 {
			parts = parts[1:]
		}
		r.inBuffer = append(r.inBuffer, parts...)
		return n
	}

	n := copy(p, data)
	if n < len(data) {
		r.inBuffer = append(r.inBuffer, data[n:])
	}
	return n
}

// readXgressChunk reads the next payload from an xgress ReadAdapter and
// extracts the edge-layer flags from the xgress payload headers.
func readXgressChunk(readAdapter *xgress.ReadAdapter) ([]byte, uint32, error) {
	data, xgHeaders, err := readAdapter.ReadPayload()
	if err != nil {
		return nil, 0, err
	}
	var flags uint32
	if flagsBytes, ok := xgHeaders[edgexg.PayloadFlagsHeader]; ok && len(flagsBytes) >= 4 {
		flags = binary.LittleEndian.Uint32(flagsBytes)
	}
	return data, flags, nil
}

// splitMultipart parses a MULTIPART_MSG chunk body. Each part is prefixed by
// a little-endian uint16 length.
func splitMultipart(data []byte) [][]byte {
	var parts [][]byte
	for len(data) > 0 {
		l := binary.LittleEndian.Uint16(data[0:2])
		data = data[2:]
		parts = append(parts, data[0:l])
		data = data[l:]
	}
	return parts
}
