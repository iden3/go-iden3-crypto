package poseidon

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPoseidonHash(t *testing.T) {
	b0 := big.NewInt(0)

	h, err := Hash([]*big.Int{b0, b0, b0, b0, b0, b0, b0, b0}, []*big.Int{b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"18586133768512220936620570745912940619677854269274689475585506675881198879027",
		h.String())
}
