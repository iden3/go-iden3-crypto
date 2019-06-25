// code originally taken from https://github.com/arnaucube/go-snark (https://github.com/arnaucube/go-snark/blob/master/fields/fq.go), pasted here to ensure compatibility among future changes

package field

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func iToBig(a int) *big.Int {
	return big.NewInt(int64(a))
}

func TestFq1(t *testing.T) {
	fq1 := NewFq(iToBig(7))

	res := fq1.Add(iToBig(4), iToBig(4))
	assert.Equal(t, iToBig(1), fq1.Affine(res))

	res = fq1.Double(iToBig(5))
	assert.Equal(t, iToBig(3), fq1.Affine(res))

	res = fq1.Sub(iToBig(5), iToBig(7))
	assert.Equal(t, iToBig(5), fq1.Affine(res))

	res = fq1.Neg(iToBig(5))
	assert.Equal(t, iToBig(2), fq1.Affine(res))

	res = fq1.Mul(iToBig(5), iToBig(11))
	assert.Equal(t, iToBig(6), fq1.Affine(res))

	res = fq1.Inverse(iToBig(4))
	assert.Equal(t, iToBig(2), res)

	res = fq1.Square(iToBig(5))
	assert.Equal(t, iToBig(4), res)
}
