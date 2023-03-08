package poseidon

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/ffg"
)

func zero() *ffg.Element {
	return ffg.NewElement()
}

var big7 = big.NewInt(7)

// exp7 performs x^7 mod p
func exp7(a *ffg.Element) {
	a.Exp(*a, big7)
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
func mix(state []*ffg.Element, opt bool) []*ffg.Element {
	mul := zero()
	newState := make([]*ffg.Element, mLen)
	for i := 0; i < mLen; i++ {
		newState[i] = zero()
	}
	for i := 0; i < mLen; i++ {
		newState[i].SetUint64(0)
		for j := 0; j < mLen; j++ {
			if opt {
				mul.Mul(P[j][i], state[j])
			} else {
				mul.Mul(M[j][i], state[j])
			}
			newState[i].Add(newState[i], mul)
		}
	}
	return newState
}

// Hash computes the hash for the given inputs
func Hash(inpBI [NROUNDSF]uint64, capBI [CAPLEN]uint64) ([CAPLEN]uint64, error) {
	state := make([]*ffg.Element, mLen)
	for i := 0; i < NROUNDSF; i++ {
		state[i] = ffg.NewElement().SetUint64(inpBI[i])
	}
	for i := 0; i < CAPLEN; i++ {
		state[i+NROUNDSF] = ffg.NewElement().SetUint64(capBI[i])
	}

	for i := 0; i < mLen; i++ {
		state[i].Add(state[i], C[i])
	}

	for r := 0; r < NROUNDSF/2; r++ {
		exp7state(state)
		ark(state, (r+1)*mLen)
		state = mix(state, r == NROUNDSF/2-1)
	}

	for r := 0; r < NROUNDSP; r++ {
		exp7(state[0])
		state[0].Add(state[0], C[(NROUNDSF/2+1)*mLen+r])

		s0 := zero()
		mul := zero()
		mul.Mul(S[(mLen*2-1)*r], state[0])
		s0.Add(s0, mul)
		for i := 1; i < mLen; i++ {
			mul.Mul(S[(mLen*2-1)*r+i], state[i])
			s0.Add(s0, mul)
			mul.Mul(S[(mLen*2-1)*r+mLen+i-1], state[0])
			state[i].Add(state[i], mul)
		}
		state[0] = s0
	}

	for r := 0; r < NROUNDSF/2; r++ {
		exp7state(state)
		if r < NROUNDSF/2-1 {
			ark(state, (NROUNDSF/2+1+r)*mLen+NROUNDSP)
		}

		state = mix(state, false)
	}

	return [CAPLEN]uint64{
		state[0].ToUint64Regular(),
		state[1].ToUint64Regular(),
		state[2].ToUint64Regular(),
		state[3].ToUint64Regular(),
	}, nil
}
