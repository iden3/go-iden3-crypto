package keccak256

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeccak256(t *testing.T) {
	const SEED = "mimc"
	res := Hash([]byte(SEED))
	assert.Equal(t,
		"b6e489e6b37224a50bebfddbe7d89fa8fdcaa84304a70bd13f79b5d9f7951e9e",
		hex.EncodeToString(res))
	c := new(big.Int).SetBytes(Hash([]byte(SEED)))
	assert.Equal(t,
		"82724731331859054037315113496710413141112897654334566532528783843265082629790",
		c.String())
}
