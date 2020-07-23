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
	assert.Equal(t, "e57ba154fb2c47811dc1a2369b27e25a44915b4e4ece4eb8ec74850cb78e01b1", hex.EncodeToString(h[:]))
}

func TestPoseidonHash(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)
	h, err := Hash([T]*big.Int{b1, b2, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t, "12242166908188651009877250812424843524687801523336557272219921456462821518061", h.String())

	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	h, err = Hash([T]*big.Int{b3, b4, b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t, "17185195740979599334254027721507328033796809509313949281114643312710535000993", h.String())
}

func TestPoseidonHashArbitraryLen(t *testing.T) {
	b1 := big.NewInt(1)
	b2 := big.NewInt(2)
	h, err := HashSlice([]*big.Int{b1, b2})
	assert.Nil(t, err)
	assert.Equal(t, "4932297968297298434239270129193057052722409868268166443802652458940273154855", h.String())

	b3 := big.NewInt(3)
	b4 := big.NewInt(4)
	h, err = HashSlice([]*big.Int{b3, b4})
	assert.Nil(t, err)
	assert.Equal(t, "4635491972858758537477743930622086396911540895966845494943021655521913507504", h.String())

	b5 := big.NewInt(5)
	b6 := big.NewInt(6)
	b7 := big.NewInt(7)
	b8 := big.NewInt(8)
	b9 := big.NewInt(9)
	b10 := big.NewInt(10)
	b11 := big.NewInt(11)
	b12 := big.NewInt(12)
	h, err = HashSlice([]*big.Int{b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12})
	assert.Nil(t, err)
	assert.Equal(t, "15278801138972282646981503374384603641625274360649669926363020545395022098027", h.String())

	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")
	n := 31
	msgElems := make([]*big.Int, 0, len(msg)/n+1)
	for i := 0; i < len(msg)/n; i++ {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg[n*i:n*(i+1)])
		msgElems = append(msgElems, v)
	}
	if len(msg)%n != 0 {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg[(len(msg)/n)*n:])
		msgElems = append(msgElems, v)
	}
	hmsg, err := HashSlice(msgElems)
	assert.Nil(t, err)
	assert.Equal(t, "16019700159595764790637132363672701294192939959594423814006267756172551741065", hmsg.String())

	msg2 := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet.")
	msg2Elems := make([]*big.Int, 0, len(msg2)/n+1)
	for i := 0; i < len(msg2)/n; i++ {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg2[n*i:n*(i+1)])
		msg2Elems = append(msg2Elems, v)
	}
	if len(msg2)%n != 0 {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg2[(len(msg2)/n)*n:])
		msg2Elems = append(msg2Elems, v)
	}
	hmsg2, err := HashSlice(msg2Elems)
	assert.Nil(t, err)
	assert.Equal(t, "2978613163687734485261639854325792381691890647104372645321246092227111432722", hmsg2.String())
}

func TestPoseidonHashArbitraryLenBrokenChunks(t *testing.T) {
	h1, err := HashSlice([]*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4),
		big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8), big.NewInt(9)})
	assert.Nil(t, err)
	h2, err := HashSlice([]*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8), big.NewInt(9),
		big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)})
	assert.Nil(t, err)
	assert.NotEqual(t, h1, h2)
}

func TestPoseidonHashArbitraryLenBrokenPadding(t *testing.T) {
	h1, err := HashSlice([]*big.Int{big.NewInt(int64(1))})
	assert.Nil(t, err)
	h2, err := HashSlice([]*big.Int{big.NewInt(int64(1)), big.NewInt(int64(0))})
	assert.Nil(t, err)
	assert.NotEqual(t, h1, h2)
}

func BenchmarkPoseidonHashSmallValues(b *testing.B) {
	b12 := big.NewInt(int64(12))
	b45 := big.NewInt(int64(45))
	b78 := big.NewInt(int64(78))
	b41 := big.NewInt(int64(41))
	bigArray4 := []*big.Int{b12, b45, b78, b41}

	for i := 0; i < b.N; i++ {
		HashSlice(bigArray4) //nolint:errcheck
	}
}

func BenchmarkPoseidonHash(b *testing.B) {
	b0 := big.NewInt(0)
	b1 := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061")
	b2 := utils.NewIntFromString("12242166908188651009877250812424843524687801523336557272219921456462821518061")

	bigArray4 := [T]*big.Int{b1, b2, b0, b0, b0, b0}

	for i := 0; i < b.N; i++ {
		Hash(bigArray4) //nolint:errcheck
	}
}
