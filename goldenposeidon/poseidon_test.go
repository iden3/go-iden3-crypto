package poseidon

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
)

const prime uint64 = 18446744069414584321

func TestPoseidonHashCompare(t *testing.T) {
	b0 := uint64(0)
	b1 := uint64(1)
	bm1 := prime - 1
	bM := prime

	h, err := Hash([NROUNDSF]uint64{b0, b0, b0, b0, b0, b0, b0, b0},
		[CAPLEN]uint64{b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			4330397376401421145,
			14124799381142128323,
			8742572140681234676,
			14345658006221440202,
		}, h,
	)

	h, err = Hash([NROUNDSF]uint64{b1, b1, b1, b1, b1, b1, b1, b1},
		[CAPLEN]uint64{b1, b1, b1, b1})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			16428316519797902711,
			13351830238340666928,
			682362844289978626,
			12150588177266359240,
		}, h,
	)

	h, err = Hash([NROUNDSF]uint64{b1, b1, b1, b1, b1, b1, b1, b1},
		[CAPLEN]uint64{b1, b1, b1, b1})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			16428316519797902711,
			13351830238340666928,
			682362844289978626,
			12150588177266359240,
		}, h,
	)

	h, err = Hash(
		[NROUNDSF]uint64{bm1, bm1, bm1, bm1, bm1, bm1, bm1, bm1},
		[CAPLEN]uint64{bm1, bm1, bm1, bm1},
	)
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			13691089994624172887,
			15662102337790434313,
			14940024623104903507,
			10772674582659927682,
		}, h,
	)

	h, err = Hash([NROUNDSF]uint64{bM, bM, bM, bM, bM, bM, bM, bM},
		[CAPLEN]uint64{b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			4330397376401421145,
			14124799381142128323,
			8742572140681234676,
			14345658006221440202,
		}, h,
	)

	h, err = Hash([NROUNDSF]uint64{
		uint64(923978),
		uint64(235763497586),
		uint64(9827635653498),
		uint64(112870),
		uint64(289273673480943876),
		uint64(230295874986745876),
		uint64(6254867324987),
		uint64(2087),
	}, [CAPLEN]uint64{b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			1892171027578617759,
			984732815927439256,
			7866041765487844082,
			8161503938059336191,
		}, h,
	)
}

func BenchmarkPoseidonHash12Inputs(b *testing.B) {
	bigArray12 := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(4),
		big.NewInt(5),
		big.NewInt(6),
		big.NewInt(7),
		big.NewInt(8),
		big.NewInt(9),
		big.NewInt(10),
		big.NewInt(11),
		big.NewInt(12),
	}

	for i := 0; i < b.N; i++ {
		poseidon.Hash(bigArray12) //nolint:errcheck,gosec
	}
}

func BenchmarkNeptuneHash(b *testing.B) {
	inp := [NROUNDSF]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	cap := [CAPLEN]uint64{10, 11, 12, 13}

	for i := 0; i < b.N; i++ {
		Hash(inp, cap) //nolint:errcheck,gosec
	}
}
