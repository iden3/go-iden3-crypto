package poseidon

import (
	"bytes"
	"errors"
	"math/big"
	"strconv"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/utils"
	"golang.org/x/crypto/blake2b"
)

const SEED = "poseidon"
const NROUNDSF = 8
const NROUNDSP = 57
const T = 6

var constC []*big.Int
var constM [T][T]*big.Int

func Zero() *big.Int {
	return new(big.Int)
}

func modQ(v *big.Int) {
	v.Mod(v, constants.Q)
}

func init() {
	constC = getPseudoRandom(SEED+"_constants", NROUNDSF+NROUNDSP)
	constM = getMDS()
}

func leByteArrayToBigInt(b []byte) *big.Int {
	res := big.NewInt(0)
	for i := 0; i < len(b); i++ {
		n := big.NewInt(int64(b[i]))
		res = new(big.Int).Add(res, new(big.Int).Lsh(n, uint(i*8)))
	}
	return res
}

func getPseudoRandom(seed string, n int) []*big.Int {
	res := make([]*big.Int, n)
	hash := blake2b.Sum256([]byte(seed))
	for i := 0; i < n; i++ {
		hashBigInt := Zero()
		res[i] = utils.SetBigIntFromLEBytes(hashBigInt, hash[:])
		modQ(res[i])
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
func getMDS() [T][T]*big.Int {
	nonce := 0
	cauchyMatrix := getPseudoRandom(SEED+"_matrix_"+nonceToString(nonce), T*2)
	for !checkAllDifferent(cauchyMatrix) {
		nonce += 1
		cauchyMatrix = getPseudoRandom(SEED+"_matrix_"+nonceToString(nonce), T*2)
	}
	var m [T][T]*big.Int
	for i := 0; i < T; i++ {
		// var mi []*big.Int
		for j := 0; j < T; j++ {
			m[i][j] = new(big.Int).Sub(cauchyMatrix[i], cauchyMatrix[T+j])
			m[i][j].ModInverse(m[i][j], constants.Q)
		}
	}
	return m
}

func checkAllDifferent(v []*big.Int) bool {
	for i := 0; i < len(v); i++ {
		if bytes.Equal(v[i].Bytes(), big.NewInt(int64(0)).Bytes()) {
			return false
		}
		for j := i + 1; j < len(v); j++ {
			if bytes.Equal(v[i].Bytes(), v[j].Bytes()) {
				return false
			}
		}
	}
	return true
}

// ark computes Add-Round Key, from the paper https://eprint.iacr.org/2019/458.pdf
func ark(state [T]*big.Int, c *big.Int) {
	for i := 0; i < T; i++ {
		modQ(state[i].Add(state[i], c))
	}
}

// cubic performs x^5 mod p
// https://eprint.iacr.org/2019/458.pdf page 8
var five = big.NewInt(5)

func cubic(a *big.Int) {
	a.Exp(a, five, constants.Q)
}

// sbox https://eprint.iacr.org/2019/458.pdf page 6
func sbox(state [T]*big.Int, i int) {
	if (i < NROUNDSF/2) || (i >= NROUNDSF/2+NROUNDSP) {
		for j := 0; j < T; j++ {
			cubic(state[j])
		}
	} else {
		cubic(state[0])
	}
}

// mix returns [[matrix]] * [vector]
func mix(state [T]*big.Int, newState [T]*big.Int, m [T][T]*big.Int) {
	mul := Zero()
	for i := 0; i < T; i++ {
		newState[i].SetInt64(0)
		for j := 0; j < T; j++ {
			modQ(mul.Mul(m[i][j], state[j]))
			newState[i].Add(newState[i], mul)
		}
		modQ(newState[i])
	}
}

// PoseidonHash computes the Poseidon hash for the given inputs
func PoseidonHash(inp [T]*big.Int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(inp[:], constants.Q) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	state := [T]*big.Int{}
	for i := 0; i < T; i++ {
		state[i] = new(big.Int).Set(inp[i])
	}

	// ARK --> SBox --> M, https://eprint.iacr.org/2019/458.pdf pag.5
	var newState [T]*big.Int
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

// Hash performs the Poseidon hash over a *big.Int array
// in chunks of 5 elements
func Hash(arr []*big.Int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(arr, constants.Q) {
		return nil, errors.New("inputs values not inside Finite Field")
	}

	r := big.NewInt(1)
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
			toHash[j] = constants.Zero
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
func HashBytes(b []byte) (*big.Int, error) {
	n := 31
	bElems := make([]*big.Int, 0, len(b)/n+1)
	for i := 0; i < len(b)/n; i++ {
		v := Zero()
		utils.SetBigIntFromLEBytes(v, b[n*i:n*(i+1)])
		bElems = append(bElems, v)
	}
	if len(b)%n != 0 {
		v := Zero()
		utils.SetBigIntFromLEBytes(v, b[(len(b)/n)*n:])
		bElems = append(bElems, v)
	}
	return Hash(bElems)
}
