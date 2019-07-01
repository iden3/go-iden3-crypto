package poseidon

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestBlake2bVersion(t *testing.T) {
	h := blake2b.Sum256([]byte("poseidon_constants"))
	assert.Equal(t, "e57ba154fb2c47811dc1a2369b27e25a44915b4e4ece4eb8ec74850cb78e01b1", hex.EncodeToString(h[:]))
}

func TestPoseidon(t *testing.T) {
	b1 := big.NewInt(int64(1))
	b2 := big.NewInt(int64(2))
	h, err := Hash([]*big.Int{b1, b2})
	assert.Nil(t, err)
	assert.Equal(t, "12242166908188651009877250812424843524687801523336557272219921456462821518061", h.String())

	b3 := big.NewInt(int64(3))
	b4 := big.NewInt(int64(4))
	h, err = Hash([]*big.Int{b3, b4})
	assert.Nil(t, err)
	assert.Equal(t, "17185195740979599334254027721507328033796809509313949281114643312710535000993", h.String())
}
