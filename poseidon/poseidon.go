package poseidon

import (
	"errors"
	"math/big"
	"strconv"

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
	return utils.NewElement().SetZero()
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
		res[i] = utils.NewElement().SetBigInt(utils.SetBigIntFromLEBytes(hashBigInt, hash[:]))
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
			m[i][j] = utils.NewElement().Sub(cauchyMatrix[i], cauchyMatrix[T+j])
			m[i][j].Inverse(m[i][j])
		}
	}
	return m
}

func checkAllDifferent(v []*ff.Element) bool {
	for i := 0; i < len(v); i++ {
		if v[i].Equal(utils.NewElement().SetZero()) {
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
// var five = big.NewInt(5)

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
func PoseidonHash(inp [T]*ff.Element) (*ff.Element, error) {
	if !utils.CheckElementArrayInField(inp[:]) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	state := [T]*ff.Element{}
	for i := 0; i < T; i++ {
		state[i] = utils.NewElement().Set(inp[i])
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
	return state[0], nil
}

// Hash performs the Poseidon hash over a ff.Element array
// in chunks of 5 elements
func Hash(arr []*ff.Element) (*ff.Element, error) {
	if !utils.CheckElementArrayInField(arr) {
		return nil, errors.New("inputs values not inside Finite Field")
	}

	r := utils.NewElement().SetOne()
	for i := 0; i < len(arr); i = i + T - 1 {
		var toHash [T]*ff.Element
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
			toHash[j] = Zero()
		}

		ph, err := PoseidonHash(toHash)
		if err != nil {
			return nil, err
		}
		r.Add(r, ph)
	}

	return r, nil
}

// HashBytes hashes a msg byte slice by blocks of 31 bytes encoded as
// little-endian
func HashBytes(b []byte) (*ff.Element, error) {
	n := 31
	bElems := make([]*ff.Element, 0, len(b)/n+1)
	for i := 0; i < len(b)/n; i++ {
		v := big.NewInt(int64(0))
		utils.SetBigIntFromLEBytes(v, b[n*i:n*(i+1)])
		bElems = append(bElems, utils.NewElement().SetBigInt(v))

	}
	if len(b)%n != 0 {
		v := big.NewInt(int64(0))
		utils.SetBigIntFromLEBytes(v, b[(len(b)/n)*n:])
		bElems = append(bElems, utils.NewElement().SetBigInt(v))
	}
	return Hash(bElems)
}
