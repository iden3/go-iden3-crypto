package ff

import "math/big"

func NewElement() *Element {
	return &Element{}
}

func (e *Element) BigInt() *big.Int {
	b := big.NewInt(0)
	e.ToBigIntRegular(b)
	return b
}
