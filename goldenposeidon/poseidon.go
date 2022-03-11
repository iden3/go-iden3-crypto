package poseidon

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/ffg"
)

const spongeChunkSize = 31
const spongeInputs = 16

func zero() *ffg.Element {
	return ffg.NewElement()
}

// exp7 performs x^7 mod p
func exp7(a *ffg.Element) {
	a.Exp(*a, big.NewInt(7)) //nolint:gomnd
}

// exp7state perform exp7 for whole state
func exp7state(state []*ffg.Element) {
	for i := 0; i < len(state); i++ {
		exp7(state[i])
	}
}

// ark computes Add-Round Key, from the paper https://eprint.iacr.org/2019/458.pdf
func ark(state []*ffg.Element, it int) {
	for i := 0; i < len(state); i++ {
		state[i].Add(state[i], C[it+i])
	}
}

// mix returns [[matrix]] * [vector]
func mix(state []*ffg.Element) []*ffg.Element {
	mul := zero()
	newState := make([]*ffg.Element, mLen)
	for i := 0; i < mLen; i++ {
		newState[i] = zero()
	}
	for i := 0; i < mLen; i++ {
		newState[i].SetUint64(0)
		for j := 0; j < mLen; j++ {
			mul.Mul(M[j][i], state[j])
			newState[i].Add(newState[i], mul)
		}
	}
	return newState
}

// Hash computes the Poseidon hash for the given inputs
func Hash(inpBI []*big.Int, capBI []*big.Int) (*big.Int, error) {
	if len(inpBI) != NROUNDSF {
		return nil, fmt.Errorf("invalid inputs length %d, must be 8", len(inpBI))
	}
	if len(capBI) != CAPLEN {
		return nil, fmt.Errorf("invalid capcity length %d, must be 4", len(capBI))
	}

	state := make([]*ffg.Element, mLen)
	for i := 0; i < NROUNDSF; i++ {
		state[i] = ffg.NewElement().SetBigInt(inpBI[i])
	}
	for i := 0; i < CAPLEN; i++ {
		state[i+NROUNDSF] = ffg.NewElement().SetBigInt(capBI[i])
	}

	for r := 0; r < NROUNDSF+NROUNDSP; r++ {
		ark(state, r*mLen)
		if r < NROUNDSF/2 || r >= NROUNDSF/2+NROUNDSP {
			exp7state(state)
		} else {
			exp7(state[0])
		}
		state = mix(state)
	}

	r := big.NewInt(0)
	for i := 0; i < CAPLEN; i++ {
		res := big.NewInt(0)
		state[i].ToBigIntRegular(res)
		r.Add(r.Lsh(r, 64), res)
	}

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
			hash, err = Hash(inputs, []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
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
		hash, err = Hash(inputs, []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)})
		if err != nil {
			return nil, err
		}
	}

	return hash, nil
}
