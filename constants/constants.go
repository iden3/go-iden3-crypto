package constants

import (
	"fmt"
	"math/big"
)

// Q is the order of the integer field (Zq) that fits inside the SNARK.
var Q *big.Int

// Zero is 0.
var Zero *big.Int

// One is 1.
var One *big.Int

// MinusOne is -1.
var MinusOne *big.Int

func init() {
	Zero = big.NewInt(0)
	One = big.NewInt(1)
	MinusOne = big.NewInt(-1)

	qString := "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	var ok bool
	Q, ok = new(big.Int).SetString(qString, 10) //nolint:gomnd
	if !ok {
		panic(fmt.Sprintf("Bad base 10 string %s", qString))
	}
}
