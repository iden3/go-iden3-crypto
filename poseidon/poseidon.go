package poseidon

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/utils"
)

// NROUNDSF constant from Poseidon paper
const NROUNDSF = 8

// NROUNDSP constant from Poseidon paper
var NROUNDSP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

const spongeChunkSize = 31
const spongeInputs = 16

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

// Hash computes the Poseidon hash for the given inputs
func Hash(inpBI []*big.Int) (*big.Int, error) {
	t := len(inpBI) + 1
	if len(inpBI) == 0 || len(inpBI) > len(NROUNDSP) {
		return nil, fmt.Errorf("invalid inputs length %d, max %d", len(inpBI), len(NROUNDSP))
	}
	if !utils.CheckBigIntArrayInField(inpBI) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	inp := utils.BigIntArrayToElementArray(inpBI)

	nRoundsF := NROUNDSF
	nRoundsP := NROUNDSP[t-2]
	C := c.c[t-2]
	S := c.s[t-2]
	M := c.m[t-2]
	P := c.p[t-2]

	state := make([]*ff.Element, t)
	state[0] = zero()
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

	rE := state[0]
	r := big.NewInt(0)
	rE.ToBigIntRegular(r)
	return r, nil
}

// HashBytes returns a sponge hash of a msg byte slice split into blocks of 31 bytes
func HashBytes(msg []byte) (*big.Int, error) {
	return HashBytesX(msg, spongeInputs)
}

// HashBytesX returns a sponge hash of a msg byte slice split into blocks of 31 bytes
func HashBytesX(msg []byte, frameSize int) (*big.Int, error) {
	if frameSize < 2 || frameSize > 16 {
		return nil, errors.New("incorrect frame size")
	}

	// not used inputs default to zero
	inputs := make([]*big.Int, frameSize)
	for j := 0; j < frameSize; j++ {
		inputs[j] = new(big.Int)
	}
	dirty := false
	var hash *big.Int
	var err error

	k := 0
	for i := 0; i < len(msg)/spongeChunkSize; i++ {
		dirty = true
		inputs[k].SetBytes(msg[spongeChunkSize*i : spongeChunkSize*(i+1)])
		if k == frameSize-1 {
			hash, err = Hash(inputs)
			dirty = false
			if err != nil {
				return nil, err
			}
			inputs = make([]*big.Int, frameSize)
			inputs[0] = hash
			for j := 1; j < frameSize; j++ {
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

// SpongeHash returns a sponge hash of inputs (using Poseidon with frame size of 16 inputs)
func SpongeHash(inputs []*big.Int) (*big.Int, error) {
	return SpongeHashX(inputs, spongeInputs)
}

// SpongeHashX returns a sponge hash of inputs using Poseidon with configurable frame size
func SpongeHashX(inputs []*big.Int, frameSize int) (*big.Int, error) {
	if frameSize < 2 || frameSize > 16 {
		return nil, errors.New("incorrect frame size")
	}

	// not used frame default to zero
	frame := make([]*big.Int, frameSize)
	for j := 0; j < frameSize; j++ {
		frame[j] = new(big.Int)
	}
	dirty := false
	var hash *big.Int
	var err error

	k := 0
	for i := 0; i < len(inputs); i++ {
		dirty = true
		frame[k] = inputs[i]
		if k == frameSize-1 {
			hash, err = Hash(frame)
			dirty = false
			if err != nil {
				return nil, err
			}
			frame = make([]*big.Int, frameSize)
			frame[0] = hash
			for j := 1; j < frameSize; j++ {
				frame[j] = new(big.Int)
			}
			k = 1
		} else {
			k++
		}
	}

	if dirty {
		// we haven't hashed something in the main sponge loop and need to do hash here
		hash, err = Hash(frame)
		if err != nil {
			return nil, err
		}
	}

	return hash, nil
}
