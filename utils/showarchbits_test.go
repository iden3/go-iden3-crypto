package utils

import (
	"fmt"
	"math/bits"
	"testing"
)

func TestShowArchBits(t *testing.T) {
	fmt.Printf("Architecture is %v bits\n", bits.UintSize)
}
