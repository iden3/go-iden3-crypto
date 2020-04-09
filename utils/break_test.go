package utils

import (
	"math/bits"
	"testing"
)

func TestBreak(t *testing.T) {
	if bits.UintSize != 64 {
		panic("bits.UintSize != 64")
	}
}
