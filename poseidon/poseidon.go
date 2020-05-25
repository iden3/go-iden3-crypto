package poseidon

import (
	"errors"
	"math/big"
	"strconv"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/utils"
	"golang.org/x/crypto/blake2b"
)

const SEED = "poseidon"
const NROUNDSF = 8
const NROUNDSP = 57
const T = 6

var constC []*ff.Element
var constM [T][T]*ff.Element

func Zero() *ff.Element {
	return ff.NewElement()
}

func modQ(v *big.Int) {
	v.Mod(v, constants.Q)
}

func init() {
	constC = getPseudoRandom(SEED+"_constants", NROUNDSF+NROUNDSP)
	constM = getMDS()
}

func getPseudoRandom(seed string, n int) []*ff.Element {
	res := make([]*ff.Element, n)
	hash := blake2b.Sum256([]byte(seed))
	for i := 0; i < n; i++ {
		hashBigInt := big.NewInt(int64(0))
		res[i] = ff.NewElement().SetBigInt(utils.SetBigIntFromLEBytes(hashBigInt, hash[:]))
		hash = blake2b.Sum256(hash[:])
	}
	return res
}

func nonceToString(n int) string {
	r := strconv.Itoa(n)
	for len(r) < 4 {
		r = "0" + r
	}
	return r
}

// https://eprint.iacr.org/2019/458.pdf pag.8
func getMDS() [T][T]*ff.Element {
	nonce := 0
	cauchyMatrix := getPseudoRandom(SEED+"_matrix_"+nonceToString(nonce), T*2)
	for !checkAllDifferent(cauchyMatrix) {
		nonce += 1
		cauchyMatrix = getPseudoRandom(SEED+"_matrix_"+nonceToString(nonce), T*2)
	}
	var m [T][T]*ff.Element
	for i := 0; i < T; i++ {
		for j := 0; j < T; j++ {
			m[i][j] = ff.NewElement().Sub(cauchyMatrix[i], cauchyMatrix[T+j])
			m[i][j].Inverse(m[i][j])
		}
	}
	return m
}

func checkAllDifferent(v []*ff.Element) bool {
	for i := 0; i < len(v); i++ {
		if v[i].Equal(ff.NewElement()) {
			return false
		}
		for j := i + 1; j < len(v); j++ {
			if v[i].Equal(v[j]) {
				return false
			}
		}
	}
	return true
}

// ark computes Add-Round Key, from the paper https://eprint.iacr.org/2019/458.pdf
func ark(state [T]*ff.Element, c *ff.Element) {
	for i := 0; i < T; i++ {
		state[i].Add(state[i], c)
	}
}

// cubic performs x^5 mod p
// https://eprint.iacr.org/2019/458.pdf page 8

func cubic(a *ff.Element) {
	a.Exp(*a, 5)
}

// sbox https://eprint.iacr.org/2019/458.pdf page 6
func sbox(state [T]*ff.Element, i int) {
	if (i < NROUNDSF/2) || (i >= NROUNDSF/2+NROUNDSP) {
		for j := 0; j < T; j++ {
			cubic(state[j])
		}
	} else {
		cubic(state[0])
	}
}

// mix returns [[matrix]] * [vector]
func mix(state [T]*ff.Element, newState [T]*ff.Element, m [T][T]*ff.Element) {
	mul := Zero()
	for i := 0; i < T; i++ {
		newState[i].SetUint64(0)
		for j := 0; j < T; j++ {
			mul.Mul(m[i][j], state[j])
			newState[i].Add(newState[i], mul)
		}
	}
}

// PoseidonHash computes the Poseidon hash for the given inputs
func PoseidonHash(inpBI [T]*big.Int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(inpBI[:]) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	inp := utils.BigIntArrayToElementArray(inpBI[:])
	state := [T]*ff.Element{}
	for i := 0; i < T; i++ {
		state[i] = ff.NewElement().Set(inp[i])
	}

	// ARK --> SBox --> M, https://eprint.iacr.org/2019/458.pdf pag.5
	var newState [T]*ff.Element
	for i := 0; i < T; i++ {
		newState[i] = Zero()
	}
	for i := 0; i < NROUNDSF+NROUNDSP; i++ {
		ark(state, constC[i])
		sbox(state, i)
		mix(state, newState, constM)
		state, newState = newState, state
	}
	rE := state[0]
	r := big.NewInt(0)
	rE.ToBigIntRegular(r)
	return r, nil
}

// Hash performs the Poseidon hash over a ff.Element array
// in chunks of 5 elements
func Hash(arr []*big.Int) (*big.Int, error) {
	r := big.NewInt(int64(1))
	for i := 0; i < len(arr); i = i + T - 1 {
		var toHash [T]*big.Int
		j := 0
		for ; j < T-1; j++ {
			if i+j >= len(arr) {
				break
			}
			toHash[j] = arr[i+j]
		}
		toHash[j] = r
		j++
		for ; j < T; j++ {
			toHash[j] = big.NewInt(0)
		}

		ph, err := PoseidonHash(toHash)
		if err != nil {
			return nil, err
		}
		modQ(r.Add(r, ph))
	}

	return r, nil
}

// HashBytes hashes a msg byte slice by blocks of 31 bytes encoded as
// little-endian
func HashBytes(b []byte) *big.Int {
	n := 31
	bElems := make([]*big.Int, 0, len(b)/n+1)
	for i := 0; i < len(b)/n; i++ {
		v := big.NewInt(int64(0))
		utils.SetBigIntFromLEBytes(v, b[n*i:n*(i+1)])
		bElems = append(bElems, v)

	}
	if len(b)%n != 0 {
		v := big.NewInt(int64(0))
		utils.SetBigIntFromLEBytes(v, b[(len(b)/n)*n:])
		bElems = append(bElems, v)
	}
	h, err := Hash(bElems)
	if err != nil {
		panic(err)
	}
	return h
}
