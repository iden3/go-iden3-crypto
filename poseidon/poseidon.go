package poseidon

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/v2/ff"
	"github.com/iden3/go-iden3-crypto/v2/utils"
)

// NROUNDSF constant from Poseidon paper
const NROUNDSF = 8

// NROUNDSP constant from Poseidon paper
var NROUNDSP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

func zero() *ff.Element {
	return ff.NewElement()
}

var big5 = big.NewInt(5)

// exp5 performs x^5 mod p
// https://eprint.iacr.org/2019/458.pdf page 8
func exp5(a *ff.Element) {
	a.Exp(*a, big5)
}

// exp5state perform exp5 for whole state
func exp5state(state []*ff.Element) {
	for i := 0; i < len(state); i++ {
		exp5(state[i])
	}
}

// ark computes Add-Round Key, from the paper https://eprint.iacr.org/2019/458.pdf
func ark(state, c []*ff.Element, it int) {
	for i := 0; i < len(state); i++ {
		state[i].Add(state[i], c[it+i])
	}
}

// mix returns [[matrix]] * [vector]
func mix(state []*ff.Element, t int, m [][]*ff.Element) []*ff.Element {
	mul := zero()
	newState := make([]*ff.Element, t)
	for i := 0; i < t; i++ {
		newState[i] = zero()
	}
	for i := 0; i < len(state); i++ {
		newState[i].SetUint64(0)
		for j := 0; j < len(state); j++ {
			mul.Mul(m[j][i], state[j])
			newState[i].Add(newState[i], mul)
		}
	}
	return newState
}

// HashWithState computes the Poseidon hash for the given inputs and initState
func HashWithState(inpBI []*big.Int, initState *big.Int) (*big.Int, error) {
	res, err := HashWithStateEx(inpBI, initState, 1)
	if err != nil {
		return nil, err
	}
	return res[0], nil
}

func HashWithStateEx(inpBI []*big.Int, initState *big.Int, nOuts int) ([]*big.Int, error) {
	t := len(inpBI) + 1
	if len(inpBI) == 0 || len(inpBI) > len(NROUNDSP) {
		return nil, fmt.Errorf("invalid inputs length %d, max %d", len(inpBI), len(NROUNDSP))
	}
	if !utils.CheckBigIntArrayInField(inpBI) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	if nOuts < 1 || nOuts > t {
		return nil, fmt.Errorf("invalid nOuts %d, min 1, max %d", nOuts, t)
	}
	inp := utils.BigIntArrayToElementArray(inpBI)

	nRoundsF := NROUNDSF
	nRoundsP := NROUNDSP[t-2]
	C := c.c[t-2]
	S := c.s[t-2]
	M := c.m[t-2]
	P := c.p[t-2]

	state := make([]*ff.Element, t)
	if !utils.CheckBigIntInField(initState) {
		return nil, errors.New("initState values not inside Finite Field")
	}

	state[0] = ff.NewElement().SetBigInt(initState)
	copy(state[1:], inp)

	ark(state, C, 0)

	for i := 0; i < nRoundsF/2-1; i++ {
		exp5state(state)
		ark(state, C, (i+1)*t)
		state = mix(state, t, M)
	}
	exp5state(state)
	ark(state, C, (nRoundsF/2)*t)
	state = mix(state, t, P)

	mul := zero()
	for i := 0; i < nRoundsP; i++ {
		exp5(state[0])
		state[0].Add(state[0], C[(nRoundsF/2+1)*t+i])

		mul.SetZero()
		newState0 := zero()
		for j := 0; j < len(state); j++ {
			mul.Mul(S[(t*2-1)*i+j], state[j])
			newState0.Add(newState0, mul)
		}

		for k := 1; k < t; k++ {
			mul.SetZero()
			state[k] = state[k].Add(state[k], mul.Mul(state[0], S[(t*2-1)*i+t+k-1]))
		}
		state[0] = newState0
	}

	for i := 0; i < nRoundsF/2-1; i++ {
		exp5state(state)
		ark(state, C, (nRoundsF/2+1)*t+nRoundsP+i*t)
		state = mix(state, t, M)
	}
	exp5state(state)
	state = mix(state, t, M)

	r := make([]*big.Int, nOuts)
	for i := 0; i < nOuts; i++ {
		rE := state[i]
		r[i] = big.NewInt(0)
		rE.ToBigIntRegular(r[i])
	}
	return r, nil
}

// Hash computes the Poseidon hash for the given inputs
func Hash(inpBI []*big.Int) (*big.Int, error) {
	return HashWithState(inpBI, big.NewInt(0))
}

// HashEx computes the Poseidon hash for the given inputs and returns
// the first nOuts outputs that include intermediate states
func HashEx(inpBI []*big.Int, nOuts int) ([]*big.Int, error) {
	return HashWithStateEx(inpBI, big.NewInt(0), nOuts)
}
