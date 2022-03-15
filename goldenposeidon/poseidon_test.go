package poseidon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const prime uint64 = 18446744069414584321

func TestPoseidonHash(t *testing.T) {
	b0 := uint64(0)
	b1 := uint64(1)
	bm1 := prime - 1
	bM := prime

	h, err := Hash([NROUNDSF]uint64{b0, b0, b0, b0, b0, b0, b0, b0}, [CAPLEN]uint64{b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			4330397376401421145,
			14124799381142128323,
			8742572140681234676,
			14345658006221440202,
		}, h,
	)

	h, err = Hash([NROUNDSF]uint64{b1, b1, b1, b1, b1, b1, b1, b1}, [CAPLEN]uint64{b1, b1, b1, b1})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			16428316519797902711,
			13351830238340666928,
			682362844289978626,
			12150588177266359240,
		}, h,
	)

	h, err = Hash([NROUNDSF]uint64{b1, b1, b1, b1, b1, b1, b1, b1}, [CAPLEN]uint64{b1, b1, b1, b1})
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

	h, err = Hash([NROUNDSF]uint64{bM, bM, bM, bM, bM, bM, bM, bM}, [CAPLEN]uint64{b0, b0, b0, b0})
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
