package poseidon

import (
	"bytes"
	"errors"
	"hash"
)

type digest struct {
	buf       *bytes.Buffer
	frameSize int
}

// Sum returns the Poseidon hash of the input bytes.
// use frame size of 16 inputs by default
func Sum(b []byte) []byte {
	h, _ := New(16)
	h.Write(b)
	return h.Sum(nil)
}

// New returns a new hash.Hash computing the Poseidon hash.
func New(frameSize int) (hash.Hash, error) {
	if frameSize < 2 || frameSize > 16 {
		return nil, errors.New("incorrect frame size")
	}
	return &digest{
		buf:       bytes.NewBuffer([]byte{}),
		frameSize: frameSize,
	}, nil
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
func (d *digest) Write(p []byte) (n int, err error) {
	return d.buf.Write(p)
}

// Sum returns the Poseidon checksum of the data.
func (d *digest) Sum(b []byte) []byte {
	hahs, err := HashBytesX(d.buf.Bytes(), d.frameSize)
	if err != nil {
		panic(err)
	}
	return append(b, hahs.Bytes()...)
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	d.buf.Reset()
}

// Size returns the number of bytes Sum will return.
func (d *digest) Size() int {
	return 32
}

// BlockSize returns the hash block size.
func (d *digest) BlockSize() int {
	return spongeChunkSize
}
