package poseidon

import (
	"bytes"
	"encoding/binary"
	"hash"
)

type hasher struct {
	buf *bytes.Buffer
}

// Sum returns the Poseidon hash of the input bytes.
func Sum(b []byte) []byte {
	h, _ := New()
	h.Write(b)
	return h.Sum(nil)
}

// New returns a new hash.Hash computing the Poseidon hash.
func New() (hash.Hash, error) {
	return &hasher{
		buf: bytes.NewBuffer([]byte{}),
	}, nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
func (h *hasher) Write(p []byte) (n int, err error) {
	return h.buf.Write(p)
}

// Sum returns the Poseidon digest of the data.
func (h *hasher) Sum(b []byte) []byte {
	var inpBI [NROUNDSF]uint64
	var capBI [CAPLEN]uint64

	requiredLen := (NROUNDSF + CAPLEN) * 8
	currentLen := h.buf.Len()
	extraBytes := currentLen % requiredLen

	// If the buffer has less than the required number of bytes or is not a multiple of requiredLen, pad it with zeros
	if extraBytes > 0 {
		padding := make([]byte, requiredLen-extraBytes)
		h.buf.Write(padding)
	}

	// Convert bytes to uint64 and fill the input arrays
	for i := 0; i < NROUNDSF; i++ {
		inpBI[i] = binary.BigEndian.Uint64(h.buf.Next(8))
	}
	for i := 0; i < CAPLEN; i++ {
		capBI[i] = binary.BigEndian.Uint64(h.buf.Next(8))
	}

	capBI, _ = Hash(inpBI, capBI)

	// Repeat the sequence if we can read more NROUNDSF*8-byte-chunks from the buffer into inpBI
	for h.buf.Len() >= requiredLen {
		for i := 0; i < NROUNDSF; i++ {
			inpBI[i] = binary.BigEndian.Uint64(h.buf.Next(8))
		}

		capBI, _ = Hash(inpBI, capBI)
	}

	capBIBytes := make([]byte, CAPLEN*8)
	for i, val := range capBI {
		binary.BigEndian.PutUint64(capBIBytes[i*8:], val)
	}

	return append(b, capBIBytes...)
}

// Reset resets the Hash to its initial state.
func (h *hasher) Reset() {
	h.buf.Reset()
}

// Size returns the number of bytes Sum will return.
func (h *hasher) Size() int {
	return CAPLEN * 8 // sizeof(uint64)
}

// BlockSize returns the hash block size.
func (h *hasher) BlockSize() int {
	return mLen * 8 // sizeof(uint64)
}
