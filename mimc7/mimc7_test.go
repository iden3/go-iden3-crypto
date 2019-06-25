package mimc7

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3/crypto/field"
	"github.com/stretchr/testify/assert"
)

func TestUtils(t *testing.T) {
	b1 := big.NewInt(int64(1))
	b2 := big.NewInt(int64(2))
	b3 := big.NewInt(int64(3))
	arrBigInt := []*big.Int{b1, b2, b3}

	// *big.Int array to RElem array
	rElems, err := BigIntsToRElems(arrBigInt)
	assert.Nil(t, err)

	// RElem array to *big.Int array
	bElems := RElemsToBigInts(rElems)

	assert.Equal(t, arrBigInt, bElems)

	r, ok := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	assert.True(t, ok)

	// greater or equal than R will give error when passing bigInts to RElems, to fit in the R Finite Field
	overR, ok := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495618", 10)
	assert.True(t, ok)
	_, err = BigIntsToRElems([]*big.Int{b1, overR, b2})
	assert.True(t, err != nil)

	_, err = BigIntsToRElems([]*big.Int{b1, r, b2})
	assert.True(t, err != nil)

	// smaller than R will not give error when passing bigInts to RElems, to fit in the R Finite Field
	underR, ok := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495616", 10)
	assert.True(t, ok)
	_, err = BigIntsToRElems([]*big.Int{b1, underR, b2})
	assert.Nil(t, err)
}

func TestMIMC7Generic(t *testing.T) {
	b1 := big.NewInt(int64(1))
	b2 := big.NewInt(int64(2))
	b3 := big.NewInt(int64(3))

	r, ok := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	assert.True(t, ok)
	fqR := field.NewFq(r)

	bigArray := []*big.Int{b1, b2, b3}
	elementsArray, err := BigIntsToRElems(bigArray)
	assert.Nil(t, err)

	// Generic Hash
	mhg, err := MIMC7HashGeneric(fqR, b1, b2, 91)
	assert.Nil(t, err)
	assert.Equal(t, "10594780656576967754230020536574539122676596303354946869887184401991294982664", mhg.String())
	hg, err := HashGeneric(fqR.Zero(), elementsArray, fqR, 91)
	assert.Nil(t, err)
	assert.Equal(t, "6464402164086696096195815557694604139393321133243036833927490113253119343397", (*big.Int)(hg).String())
}

func TestMIMC7(t *testing.T) {
	b12 := big.NewInt(int64(12))
	b45 := big.NewInt(int64(45))
	b78 := big.NewInt(int64(78))
	b41 := big.NewInt(int64(41))

	// h1, hash of 1 elements
	bigArray1 := []*big.Int{b12}
	elementsArray1, err := BigIntsToRElems(bigArray1)
	assert.Nil(t, err)

	h1 := Hash(elementsArray1, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h1).Bytes()), "0x237c92644dbddb86d8a259e0e923aaab65a93f1ec5758b8799988894ac0958fd")

	// h2a, hash of 2 elements
	bigArray2a := []*big.Int{b78, b41}
	elementsArray2a, err := BigIntsToRElems(bigArray2a)
	assert.Nil(t, err)

	mh2a := MIMC7Hash(b12, b45)
	assert.Nil(t, err)
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(mh2a).Bytes()), "0x2ba7ebad3c6b6f5a20bdecba2333c63173ca1a5f2f49d958081d9fa7179c44e4")

	h2a := Hash(elementsArray2a, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h2a).Bytes()), "0x067f3202335ea256ae6e6aadcd2d5f7f4b06a00b2d1e0de903980d5ab552dc70")

	// h2b, hash of 2 elements
	bigArray2b := []*big.Int{b12, b45}
	elementsArray2b, err := BigIntsToRElems(bigArray2b)
	assert.Nil(t, err)

	mh2b := MIMC7Hash(b12, b45)
	assert.Nil(t, err)
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(mh2b).Bytes()), "0x2ba7ebad3c6b6f5a20bdecba2333c63173ca1a5f2f49d958081d9fa7179c44e4")

	h2b := Hash(elementsArray2b, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h2b).Bytes()), "0x15ff7fe9793346a17c3150804bcb36d161c8662b110c50f55ccb7113948d8879")

	// h4, hash of 4 elements
	bigArray4 := []*big.Int{b12, b45, b78, b41}
	elementsArray4, err := BigIntsToRElems(bigArray4)
	assert.Nil(t, err)

	h4 := Hash(elementsArray4, nil)
	assert.Nil(t, err)
	// same hash value than the iden3js and circomlib tests:
	assert.Equal(t, "0x"+hex.EncodeToString((*big.Int)(h4).Bytes()), "0x284bc1f34f335933a23a433b6ff3ee179d682cd5e5e2fcdd2d964afa85104beb")
}

func BenchmarkMIMC7(b *testing.B) {
	b12 := big.NewInt(int64(12))
	b45 := big.NewInt(int64(45))
	b78 := big.NewInt(int64(78))
	b41 := big.NewInt(int64(41))
	bigArray4 := []*big.Int{b12, b45, b78, b41}
	elementsArray4, err := BigIntsToRElems(bigArray4)
	assert.Nil(b, err)

	var h4 RElem
	for i := 0; i < b.N; i++ {
		h4 = Hash(elementsArray4, nil)
	}
	println(h4)
}
