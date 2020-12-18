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
		"11043376183861534927536506085090418075369306574649619885724436265926427398571",
		h.String())

	h, err = Hash([]*big.Int{b1, b2})
	assert.Nil(t, err)
	assert.Equal(t,
		"17117985411748610629288516079940078114952304104811071254131751175361957805920",
		h.String())

	h, err = Hash([]*big.Int{b1, b2, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"3975478831357328722254985704342968745327876719981393787143845259590563829094",
		h.String())
	h, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"19772360636270345724087386688434825760738403416279047262510528378903625000110",
		h.String())

	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	h, err = Hash([]*big.Int{b3, b4, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"3181200837746671699652342497997860344148947482942465819251904554707352676086",
		h.String())
	h, err = Hash([]*big.Int{b3, b4, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		"8386348873272147968934270337233829407378789978142456170950021426339096575008",
		h.String())

	b5 := big.NewInt(5)
	b6 := big.NewInt(6)
	h, err = Hash([]*big.Int{b1, b2, b3, b4, b5, b6})
	assert.Nil(t, err)
	assert.Equal(t,
		"5202465217520500374834597824465244016759843635092906214933648999760272616044",
		h.String())
}

func TestErrorInputs(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)

	_, err := Hash([]*big.Int{b1, b2, b0, b0, b0, b0})
	assert.Nil(t, err)

	_, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0})
	assert.NotNil(t, err)
	assert.Equal(t, "invalid inputs length 7, max 7", err.Error())

	_, err = Hash([]*big.Int{b1, b2, b0, b0, b0, b0, b0, b0})
	assert.NotNil(t, err)
	assert.Equal(t, "invalid inputs length 8, max 7", err.Error())
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
