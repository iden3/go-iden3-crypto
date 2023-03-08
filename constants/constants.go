package constants

import (
	"math/big"
)

const qString = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

// Q is the order of the integer field (Zq) that fits inside the SNARK.
var Q, _ = new(big.Int).SetString(qString, 10)

// Zero is 0.
var Zero = big.NewInt(0)

// One is 1.
var One = big.NewInt(1)

// MinusOne is -1.
var MinusOne = big.NewInt(-1)
