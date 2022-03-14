package poseidon

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPoseidonHash(t *testing.T) {
	b0 := big.NewInt(0)
	b1 := big.NewInt(1)
	b_1 := big.NewInt(-1)
	bM := new(big.Int).SetUint64(18446744069414584321)

	h, err := Hash([]*big.Int{b0, b0, b0, b0, b0, b0, b0, b0}, []*big.Int{b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			4330397376401421145,
			14124799381142128323,
			8742572140681234676,
			14345658006221440202,
		}, h,
	)

	h, err = Hash([]*big.Int{b1, b1, b1, b1, b1, b1, b1, b1}, []*big.Int{b1, b1, b1, b1})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			16428316519797902711,
			13351830238340666928,
			682362844289978626,
			12150588177266359240,
		}, h,
	)

	h, err = Hash([]*big.Int{b1, b1, b1, b1, b1, b1, b1, b1}, []*big.Int{b1, b1, b1, b1})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			16428316519797902711,
			13351830238340666928,
			682362844289978626,
			12150588177266359240,
		}, h,
	)

	h, err = Hash([]*big.Int{b_1, b_1, b_1, b_1, b_1, b_1, b_1, b_1}, []*big.Int{b_1, b_1, b_1, b_1})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			13691089994624172887,
			15662102337790434313,
			14940024623104903507,
			10772674582659927682,
		}, h,
	)

	h, err = Hash([]*big.Int{bM, bM, bM, bM, bM, bM, bM, bM}, []*big.Int{b0, b0, b0, b0})
	assert.Nil(t, err)
	assert.Equal(t,
		[CAPLEN]uint64{
			4330397376401421145,
			14124799381142128323,
			8742572140681234676,
			14345658006221440202,
		}, h,
	)

	h, err = Hash([]*big.Int{
		new(big.Int).SetUint64(923978),
		new(big.Int).SetUint64(235763497586),
		new(big.Int).SetUint64(9827635653498),
		new(big.Int).SetUint64(112870),
		new(big.Int).SetUint64(289273673480943876),
		new(big.Int).SetUint64(230295874986745876),
		new(big.Int).SetUint64(6254867324987),
		new(big.Int).SetUint64(2087),
	}, []*big.Int{b0, b0, b0, b0})
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
