// This package is a wrapper for poseidon package.
// It is used to implement the standart golang inerface Hash.


package poseidon

import (
	"bytes"
	"hash"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

type digest struct {
	buf *bytes.Buffer
}

// NewPoseidon returns the Poseidon hash of the input bytes.
func NewPoseidon(b []byte) []byte {
	h := New()
	h.Write(b)
	return h.Sum(nil)
}

// New returns a new hash.Hash computing the Poseidon hash.
func New() hash.Hash {
	return &digest{
		buf: bytes.NewBuffer([]byte{}),
	}
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
func (d *digest) Write(p []byte) (n int, err error) {
	return d.buf.Write(p)
}

// Sum returns the Poseidon checksum of the data.
func (d *digest) Sum(b []byte) []byte {
	hahs, err := poseidon.HashBytes(d.buf.Bytes())
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
	return 31
}
