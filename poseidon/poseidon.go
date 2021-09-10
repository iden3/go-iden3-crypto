package poseidon

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/utils"
)

const NROUNDSF = 8 //nolint:golint

var NROUNDSP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68} //nolint:golint

func zero() *ff.Element {
	return ff.NewElement()
}

// ark computes Add-Round Key, from the paper https://eprint.iacr.org/2019/458.pdf
func ark(state []*ff.Element, c []*ff.Element, it int) {
	for i := 0; i < len(state); i++ {
		state[i].Add(state[i], c[it+i])
	}
}

// exp5 performs x^5 mod p
// https://eprint.iacr.org/2019/458.pdf page 8
func exp5(a *ff.Element) {
	a.Exp(*a, 5)
}

// sbox https://eprint.iacr.org/2019/458.pdf page 6
func sbox(nRoundsF, nRoundsP int, state []*ff.Element, i int) {
	if (i < nRoundsF/2) || (i >= nRoundsF/2+nRoundsP) {
		for j := 0; j < len(state); j++ {
			exp5(state[j])
		}
	} else {
		exp5(state[0])
	}
}

// mix returns [[matrix]] * [vector]
func mix(state []*ff.Element, newState []*ff.Element, m [][]*ff.Element) {
	mul := zero()
	for i := 0; i < len(state); i++ {
		newState[i].SetUint64(0)
		for j := 0; j < len(state); j++ {
			mul.Mul(m[i][j], state[j])
			newState[i].Add(newState[i], mul)
		}
	}
}

// Hash computes the Poseidon hash for the given inputs
func Hash(inpBI []*big.Int) (*big.Int, error) {
	t := len(inpBI) + 1
	if len(inpBI) == 0 || len(inpBI) >= len(NROUNDSP)-1 {
		return nil, fmt.Errorf("invalid inputs length %d, max %d", len(inpBI), len(NROUNDSP)-2)
	}
	if !utils.CheckBigIntArrayInField(inpBI[:]) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	inp := utils.BigIntArrayToElementArray(inpBI[:])
	state := make([]*ff.Element, t)
	state[0] = zero()
	copy(state[1:], inp[:])

	nRoundsF := NROUNDSF
	nRoundsP := NROUNDSP[t-2]

	newState := make([]*ff.Element, t)
	for i := 0; i < t; i++ {
		newState[i] = zero()
	}

	// ARK --> SBox --> M, https://eprint.iacr.org/2019/458.pdf pag.5
	for i := 0; i < nRoundsF+nRoundsP; i++ {
		ark(state, c.c[t-2], i*t)
		sbox(nRoundsF, nRoundsP, state, i)
		mix(state, newState, c.m[t-2])
		state, newState = newState, state
	}
	rE := state[0]
	r := big.NewInt(0)
	rE.ToBigIntRegular(r)
	return r, nil
}
