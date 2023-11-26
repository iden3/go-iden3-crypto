package poseidon

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const prime uint64 = 18446744069414584321
const b0 = uint64(0)
const b1 = uint64(1)
const bm1 = prime - 1
const bM = prime

type testInputBytes struct {
	inpBi [NROUNDSF]uint64
	capBi [CAPLEN]uint64
}

type testVector struct {
	bytes        testInputBytes
	expectedHash [CAPLEN]uint64
}

var testVectors = []testVector{
	{
		bytes: testInputBytes{
			inpBi: [NROUNDSF]uint64{b0, b0, b0, b0, b0, b0, b0, b0},
			capBi: [CAPLEN]uint64{b0, b0, b0, b0},
		},
		expectedHash: [CAPLEN]uint64{
			4330397376401421145,
			14124799381142128323,
			8742572140681234676,
			14345658006221440202,
		},
	},
	{
		bytes: testInputBytes{
			inpBi: [NROUNDSF]uint64{b1, b1, b1, b1, b1, b1, b1, b1},
			capBi: [CAPLEN]uint64{b1, b1, b1, b1},
		},
		expectedHash: [CAPLEN]uint64{
			16428316519797902711,
			13351830238340666928,
			682362844289978626,
			12150588177266359240,
		},
	},
	{
		bytes: testInputBytes{
			inpBi: [NROUNDSF]uint64{bm1, bm1, bm1, bm1, bm1, bm1, bm1, bm1},
			capBi: [CAPLEN]uint64{bm1, bm1, bm1, bm1},
		},
		expectedHash: [CAPLEN]uint64{
			13691089994624172887,
			15662102337790434313,
			14940024623104903507,
			10772674582659927682,
		},
	},
	{
		bytes: testInputBytes{
			inpBi: [NROUNDSF]uint64{bM, bM, bM, bM, bM, bM, bM, bM},
			capBi: [CAPLEN]uint64{b0, b0, b0, b0},
		},
		expectedHash: [CAPLEN]uint64{
			4330397376401421145,
			14124799381142128323,
			8742572140681234676,
			14345658006221440202,
		},
	},
	{
		bytes: testInputBytes{
			inpBi: [NROUNDSF]uint64{uint64(923978),
				uint64(235763497586),
				uint64(9827635653498),
				uint64(112870),
				uint64(289273673480943876),
				uint64(230295874986745876),
				uint64(6254867324987),
				uint64(2087)},
			capBi: [CAPLEN]uint64{b0, b0, b0, b0},
		},
		expectedHash: [CAPLEN]uint64{
			1892171027578617759,
			984732815927439256,
			7866041765487844082,
			8161503938059336191,
		},
	},
}

func TestPoseidonHashCompare(t *testing.T) {
	for i, vector := range testVectors {
		t.Run(fmt.Sprintf("test vector %d", i), func(t *testing.T) {
			h, err := Hash(vector.bytes.inpBi, vector.bytes.capBi)
			assert.Nil(t, err)
			assert.Equal(t, vector.expectedHash, h)
		})
	}
}

func BenchmarkNeptuneHash(b *testing.B) {
	inp := [NROUNDSF]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	_cap := [CAPLEN]uint64{10, 11, 12, 13}

	for i := 0; i < b.N; i++ {
		_, _ = Hash(inp, _cap)
	}
}
