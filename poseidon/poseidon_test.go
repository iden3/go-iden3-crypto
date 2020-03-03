package poseidon

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/blake2b"
)

func TestBlake2bVersion(t *testing.T) {
	h := blake2b.Sum256([]byte("poseidon_constants"))
	assert.Equal(t, "e57ba154fb2c47811dc1a2369b27e25a44915b4e4ece4eb8ec74850cb78e01b1", hex.EncodeToString(h[:]))
}

func TestPoseidon(t *testing.T) {
	b1 := utils.NewElement().SetUint64(1)
	b2 := utils.NewElement().SetUint64(2)
	h, err := Hash([]*ff.Element{b1, b2})
	assert.Nil(t, err)
	assert.Equal(t, "4932297968297298434239270129193057052722409868268166443802652458940273154855", h.String())

	b3 := utils.NewElement().SetUint64(3)
	b4 := utils.NewElement().SetUint64(4)
	h, err = Hash([]*ff.Element{b3, b4})
	assert.Nil(t, err)
	assert.Equal(t, "4635491972858758537477743930622086396911540895966845494943021655521913507504", h.String())

	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.")
	n := 31
	msgElems := make([]*ff.Element, 0, len(msg)/n+1)
	for i := 0; i < len(msg)/n; i++ {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg[n*i:n*(i+1)])
		msgElems = append(msgElems, utils.NewElement().SetBigInt(v))
	}
	if len(msg)%n != 0 {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg[(len(msg)/n)*n:])
		msgElems = append(msgElems, utils.NewElement().SetBigInt(v))
	}
	hmsg, err := Hash(msgElems)
	assert.Nil(t, err)
	assert.Equal(t, "16019700159595764790637132363672701294192939959594423814006267756172551741065", hmsg.String())

	msg2 := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet.")
	msg2Elems := make([]*ff.Element, 0, len(msg2)/n+1)
	for i := 0; i < len(msg2)/n; i++ {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg2[n*i:n*(i+1)])
		msg2Elems = append(msg2Elems, utils.NewElement().SetBigInt(v))
	}
	if len(msg2)%n != 0 {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, msg2[(len(msg2)/n)*n:])
		msg2Elems = append(msg2Elems, utils.NewElement().SetBigInt(v))
	}
	hmsg2, err := Hash(msg2Elems)
	assert.Nil(t, err)
	assert.Equal(t, "2978613163687734485261639854325792381691890647104372645321246092227111432722", hmsg2.String())

	hmsg2, err = HashBytes(msg2)
	assert.Nil(t, err)
	assert.Equal(t, "2978613163687734485261639854325792381691890647104372645321246092227111432722", hmsg2.String())
}

func TestPoseidonBrokenChunks(t *testing.T) {
	h1, err := Hash([]*ff.Element{utils.NewElement().SetUint64(0), utils.NewElement().SetUint64(1), utils.NewElement().SetUint64(2), utils.NewElement().SetUint64(3), utils.NewElement().SetUint64(4),
		utils.NewElement().SetUint64(5), utils.NewElement().SetUint64(6), utils.NewElement().SetUint64(7), utils.NewElement().SetUint64(8), utils.NewElement().SetUint64(9)})
	assert.Nil(t, err)
	h2, err := Hash([]*ff.Element{utils.NewElement().SetUint64(5), utils.NewElement().SetUint64(6), utils.NewElement().SetUint64(7), utils.NewElement().SetUint64(8), utils.NewElement().SetUint64(9),
		utils.NewElement().SetUint64(0), utils.NewElement().SetUint64(1), utils.NewElement().SetUint64(2), utils.NewElement().SetUint64(3), utils.NewElement().SetUint64(4)})
	assert.Nil(t, err)
	assert.NotEqual(t, h1, h2)
}

func TestPoseidonBrokenPadding(t *testing.T) {
	h1, err := Hash([]*ff.Element{utils.NewElement().SetUint64(1)})
	assert.Nil(t, err)
	h2, err := Hash([]*ff.Element{utils.NewElement().SetUint64(1), utils.NewElement().SetUint64(0)})
	assert.Nil(t, err)
	assert.NotEqual(t, h1, h2)
}

func BenchmarkPoseidon(b *testing.B) {
	b12 := utils.NewElement().SetUint64(12)
	b45 := utils.NewElement().SetUint64(45)
	b78 := utils.NewElement().SetUint64(78)
	b41 := utils.NewElement().SetUint64(41)
	bigArray4 := []*ff.Element{b12, b45, b78, b41}

	for i := 0; i < b.N; i++ {
		Hash(bigArray4)
	}
}

func BenchmarkPoseidonLarge(b *testing.B) {
	b12 := utils.NewElement().SetString("11384336176656855268977457483345535180380036354188103142384839473266348197733")
	b45 := utils.NewElement().SetString("11384336176656855268977457483345535180380036354188103142384839473266348197733")
	b78 := utils.NewElement().SetString("11384336176656855268977457483345535180380036354188103142384839473266348197733")
	b41 := utils.NewElement().SetString("11384336176656855268977457483345535180380036354188103142384839473266348197733")
	bigArray4 := []*ff.Element{b12, b45, b78, b41}

	for i := 0; i < b.N; i++ {
		Hash(bigArray4)
	}
}
