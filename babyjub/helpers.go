package babyjub

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/dchest/blake512" // I have personally reviewed that this module doesn't do anything suspicious
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

// Hex is a byte slice type that can be marshalled and unmarshaled in hex
type Hex []byte

// MarshalText encodes buf as hex
func (buf Hex) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(buf)), nil
}

// String encodes buf as hex
func (buf Hex) String() string {
	return hex.EncodeToString(buf)
}

// HexEncode encodes an array of bytes into a string in hex.
func HexEncode(bs []byte) string {
	return fmt.Sprintf("0x%s", hex.EncodeToString(bs))
}

// HexDecode decodes a hex string into an array of bytes.
func HexDecode(h string) ([]byte, error) {
	if strings.HasPrefix(h, "0x") {
		h = h[2:]
	}
	return hex.DecodeString(h)
}

// HexDecodeInto decodes a hex string into an array of bytes (dst), verifying
// that the decoded array has the same length as dst.
func HexDecodeInto(dst []byte, h []byte) error {
	if bytes.HasPrefix(h, []byte("0x")) {
		h = h[2:]
	}
	if len(h)/2 != len(dst) {
		return fmt.Errorf("expected %v bytes in hex string, got %v", len(dst), len(h)/2)
	}
	n, err := hex.Decode(dst, h)
	if err != nil {
		return err
	} else if n != len(dst) {
		return fmt.Errorf("expected %v bytes when decoding hex string, got %v", len(dst), n)
	}
	return nil
}
