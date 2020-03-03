package utils

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/ff"
)

// NewIntFromString creates a new big.Int from a decimal integer encoded as a
// string.  It will panic if the string is not a decimal integer.
func NewIntFromString(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Sprintf("Bad base 10 string %s", s))
	}
	return v
}

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

// CheckBigIntInField checks if given *big.Int fits in a Field Q element
func CheckBigIntInField(a *big.Int) bool {
	if a.Cmp(constants.Q) != -1 {
		return false
	}
	return true
}

// CheckBigIntArrayInField checks if given *big.Int fits in a Field Q element
func CheckBigIntArrayInField(arr []*big.Int) bool {
	for _, a := range arr {
		if !CheckBigIntInField(a) {
			return false
		}
	}
	return true
}

// CheckElementArrayInField checks if given *ff.Element fits in a Field Q element
func CheckElementArrayInField(arr []*ff.Element) bool {
	for _, aE := range arr {
		a := big.NewInt(0)
		aE.ToBigIntRegular(a)
		if !CheckBigIntInField(a) {
			return false
		}
	}
	return true
}

func NewElement() *ff.Element {
	return &ff.Element{0, 0, 0, 0}
}
