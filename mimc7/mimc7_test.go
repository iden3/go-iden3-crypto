package mimc7

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestKeccak256(t *testing.T) {
	res := crypto.Keccak256([]byte(SEED))
	assert.Equal(t,
		"b6e489e6b37224a50bebfddbe7d89fa8fdcaa84304a70bd13f79b5d9f7951e9e",
		hex.EncodeToString(res))
	c := new(big.Int).SetBytes(crypto.Keccak256([]byte(SEED)))
	assert.Equal(t,
		"82724731331859054037315113496710413141112897654334566532528783843265082629790",
		c.String())
}

func TestMIMC7Generic(t *testing.T) {
	b1 := big.NewInt(int64(1))
	b2 := big.NewInt(int64(2))
	b3 := big.NewInt(int64(3))

	bigArray := []*big.Int{b1, b2, b3}

	// Generic Hash
	mhg := MIMC7HashGeneric(b1, b2, 91)
	assert.Equal(t,
		"10594780656576967754230020536574539122676596303354946869887184401991294982664",
		mhg.String())
	hg, err := HashGeneric(big.NewInt(0), bigArray, 91)
	assert.Nil(t, err)
	assert.Equal(t,
		"6464402164086696096195815557694604139393321133243036833927490113253119343397",
		(*big.Int)(hg).String())
}

func TestMIMC7(t *testing.T) {
	b12 := big.NewInt(int64(12))
	b45 := big.NewInt(int64(45))
	b78 := big.NewInt(int64(78))
	b41 := big.NewInt(int64(41))

	// h1, hash of 1 elements
	bigArray1 := []*big.Int{b12}

	h1, err := Hash(bigArray1, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h1).Bytes()),
		"0x237c92644dbddb86d8a259e0e923aaab65a93f1ec5758b8799988894ac0958fd")

	// h2a, hash of 2 elements
	bigArray2a := []*big.Int{b78, b41}

	h2a, err := Hash(bigArray2a, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h2a).Bytes()),
		"0x067f3202335ea256ae6e6aadcd2d5f7f4b06a00b2d1e0de903980d5ab552dc70")

	// h2b, hash of 2 elements
	bigArray2b := []*big.Int{b12, b45}

	mh2b := MIMC7Hash(b12, b45)
	assert.Nil(t, err)
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(mh2b).Bytes()),
		"0x2ba7ebad3c6b6f5a20bdecba2333c63173ca1a5f2f49d958081d9fa7179c44e4")

	h2b, err := Hash(bigArray2b, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h2b).Bytes()),
		"0x15ff7fe9793346a17c3150804bcb36d161c8662b110c50f55ccb7113948d8879")

	// h4, hash of 4 elements
	bigArray4 := []*big.Int{b12, b45, b78, b41}

	h4, err := Hash(bigArray4, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h4).Bytes()),
		"0x284bc1f34f335933a23a433b6ff3ee179d682cd5e5e2fcdd2d964afa85104beb")

	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.") //nolint:lll
	hmsg := HashBytes(msg)
	assert.Equal(t,
		"16855787120419064316734350414336285711017110414939748784029922801367685456065",
		hmsg.String())
}

func BenchmarkMIMC7(b *testing.B) {
	b12 := big.NewInt(int64(12))
	b45 := big.NewInt(int64(45))
	b78 := big.NewInt(int64(78))
	b41 := big.NewInt(int64(41))
	bigArray4 := []*big.Int{b12, b45, b78, b41}

	for i := 0; i < b.N; i++ {
		Hash(bigArray4, nil) //nolint:errcheck,gosec
	}
}
