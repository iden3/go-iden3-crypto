package poseidon

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestBlake2bVersion(t *testing.T) {
	h := blake2b.Sum256([]byte("poseidon_constants"))
	assert.Equal(t,
		"e57ba154fb2c47811dc1a2369b27e25a44915b4e4ece4eb8ec74850cb78e01b1",
		hex.EncodeToString(h[:]))
}

func TestPoseidonHash(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)

	h, err := Hash([]*big.Int{b1})
	assert.Nil(t, err)
	assert.Equal(t,
		"18586133768512220936620570745912940619677854269274689475585506675881198879027",
		h.String())

	h, err = Hash([]*big.Int{b1, b2})
	assert.Nil(t, err)
	assert.Equal(t,
		"7853200120776062878684798364095072458815029376092732009249414926327459813530",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"1018317224307729531995786483840663576608797660851238720571059489595066344487",
		h.String())
	h, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"15336558801450556532856248569924170992202208561737609669134139141992924267169",
		h.String())

	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	h, err = Hash([]*big.Int{b3, b4, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"5811595552068139067952687508729883632420015185677766880877743348592482390548",
		h.String())
	h, err = Hash([]*big.Int{b3, b4, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"12263118664590987767234828103155242843640892839966517009184493198782366909018",
		h.String())

	b5 := big.NewInt(5)
	b6 := big.NewInt(6)
	h, err = Hash([]*big.Int{b1, b2, b3, b4, b5, b6})
	assert.Nil(t, err)
	assert.Equal(t,
		"20400040500897583745843009878988256314335038853985262692600694741116813247201",
		h.String())
}

func TestErrorInputs(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)

	_, err := Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0})
	assert.Nil(t, err)

	_, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0})
	assert.NotNil(t, err)
	assert.Equal(t, "invalid inputs length 15, max 14", err.Error())

	_, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0, b0})
	assert.NotNil(t, err)
	assert.Equal(t, "invalid inputs length 16, max 14", err.Error())
}

func BenchmarkPoseidonHash(b *testing.B) {
	b0 := big.NewInt(0)
	b1 := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061") //nolint:lll
	b2 := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061") //nolint:lll

	bigArray4 := []*big.Int{b1, b2, b0, b0, b0, b0}

	for i := 0; i < b.N; i++ {
		Hash(bigArray4) //nolint:errcheck,gosec
	}
}
