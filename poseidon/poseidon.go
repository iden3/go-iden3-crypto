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

const spongeChunkSize = 31
const spongeInputs = 16

func zero() *ff.Element {
	return ff.NewElement()
}

// exp5 performs x^5 mod p
// https://eprint.iacr.org/2019/458.pdf page 8
func exp5(a *ff.Element) {
	a.Exp(*a, big.NewInt(5)) //nolint:gomnd
}

// exp5state perform exp5 for whole state
func exp5state(state []*ff.Element) {
	for i := 0; i < len(state); i++ {
		exp5(state[i])
	}
}

// ark computes Add-Round Key, from the paper https://eprint.iacr.org/2019/458.pdf
func ark(state []*ff.Element, c []*ff.Element, it int) {
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

// Hash computes the Poseidon hash for the given inputs
func Hash(inpBI []*big.Int) (*big.Int, error) {
	t := len(inpBI) + 1
	if len(inpBI) == 0 || len(inpBI) > len(NROUNDSP) {
		return nil, fmt.Errorf("invalid inputs length %d, max %d", len(inpBI), len(NROUNDSP)) //nolint:gomnd,lll
	}
	if !utils.CheckBigIntArrayInField(inpBI[:]) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	inp := utils.BigIntArrayToElementArray(inpBI[:])

	nRoundsF := NROUNDSF
	nRoundsP := NROUNDSP[t-2]
	C := c.c[t-2]
	S := c.s[t-2]
	M := c.m[t-2]
	P := c.p[t-2]

	state := make([]*ff.Element, t)
	state[0] = zero()
	copy(state[1:], inp[:])

	ark(state, C, 0)

	for i := 0; i < nRoundsF/2-1; i++ {
		exp5state(state)
		ark(state, C, (i+1)*t)
		state = mix(state, t, M)
	}
	exp5state(state)
	ark(state, C, (nRoundsF/2)*t)
	state = mix(state, t, P)

	for i := 0; i < nRoundsP; i++ {
		exp5(state[0])
		state[0].Add(state[0], C[(nRoundsF/2+1)*t+i])

		mul := zero()
		newState0 := zero()
		for j := 0; j < len(state); j++ {
			mul.Mul(S[(t*2-1)*i+j], state[j])
			newState0.Add(newState0, mul)
		}

		for k := 1; k < t; k++ {
			mul = zero()
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

	rE := state[0]
	r := big.NewInt(0)
	rE.ToBigIntRegular(r)
	return r, nil
}

// HashBytes returns a sponge hash of a msg byte slice split into blocks of 31 bytes
func HashBytes(msg []byte) (*big.Int, error) {
	// not used inputs default to zero
	inputs := make([]*big.Int, spongeInputs)
	for j := 0; j < spongeInputs; j++ {
		inputs[j] = new(big.Int)
	}
	dirty := false
	var hash *big.Int
	var err error

	k := 0
	for i := 0; i < len(msg)/spongeChunkSize; i++ {
		dirty = true
		inputs[k].SetBytes(msg[spongeChunkSize*i : spongeChunkSize*(i+1)])
		if k == spongeInputs-1 {
			hash, err = Hash(inputs)
			dirty = false
			if err != nil {
				return nil, err
			}
			inputs = make([]*big.Int, spongeInputs)
			inputs[0] = hash
			for j := 1; j < spongeInputs; j++ {
				inputs[j] = new(big.Int)
			}
			k = 1
		} else {
			k++
		}
	}

	if len(msg)%spongeChunkSize != 0 {
		// the last chunk of the message is less than 31 bytes
		// zero padding it, so that 0xdeadbeaf becomes
		// 0xdeadbeaf000000000000000000000000000000000000000000000000000000
		var buf [spongeChunkSize]byte
		copy(buf[:], msg[(len(msg)/spongeChunkSize)*spongeChunkSize:])
		inputs[k] = new(big.Int).SetBytes(buf[:])
		dirty = true
	}

	if dirty {
		// we haven't hashed something in the main sponge loop and need to do hash here
		hash, err = Hash(inputs)
		if err != nil {
			return nil, err
		}
	}

	return hash, nil
}
