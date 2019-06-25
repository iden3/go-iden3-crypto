package babyjub

import (
	"github.com/dchest/blake512" // I have personally reviewed that this module doesn't do anything suspicious
	"math/big"
)

// SwapEndianness swaps the endianness of the value encoded in xs.  If xs is
// Big-Endian, the result will be Little-Endian and viceversa.
func SwapEndianness(xs []byte) []byte {
	ys := make([]byte, len(xs))
	for i, b := range xs {
		ys[len(xs)-1-i] = b
	}
	return ys
}

// BigIntLEBytes encodes a big.Int into an array in Little-Endian.
func BigIntLEBytes(v *big.Int) [32]byte {
	le := SwapEndianness(v.Bytes())
	res := [32]byte{}
	copy(res[:], le)
	return res
}

// SetBigIntFromLEBytes sets the value of a big.Int from a Little-Endian
// encoded value.
func SetBigIntFromLEBytes(v *big.Int, leBuf []byte) *big.Int {
	beBuf := SwapEndianness(leBuf)
	return v.SetBytes(beBuf)
}

// Blake512 performs the blake-512 hash over the buffer m.  Note that this is
// the original blake from the SHA3 competition and not the new blake2 version.
func Blake512(m []byte) []byte {
	h := blake512.New()
	h.Write(m[:])
	return h.Sum(nil)
}
