package poseidon

import (
	"bytes"
	"errors"
	"math/big"
	"strconv"

	_constants "github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/field"
	"github.com/iden3/go-iden3-crypto/utils"
	"golang.org/x/crypto/blake2b"
)

const SEED = "poseidon"
const NROUNDSF = 8
const NROUNDSP = 57
const T = 6

var constants = generateConstantsData()

type constantsData struct {
	fqR field.Fq
	c   []*big.Int
	m   [][]*big.Int
}

func generateConstantsData() constantsData {
	var constants constantsData

	fqR := field.NewFq(_constants.Q)
	constants.fqR = fqR
	constants.c = getPseudoRandom(fqR, SEED+"_constants", NROUNDSF+NROUNDSP)
	constants.m = getMDS(fqR)

	return constants
}

func leByteArrayToBigInt(b []byte) *big.Int {
	res := big.NewInt(0)
	for i := 0; i < len(b); i++ {
		n := big.NewInt(int64(b[i]))
		res = new(big.Int).Add(res, new(big.Int).Lsh(n, uint(i*8)))
	}
	return res
}

func getPseudoRandom(fqR field.Fq, seed string, n int) []*big.Int {
	var res []*big.Int
	hash := blake2b.Sum256([]byte(seed))
	for len(res) < n {
		hashBigInt := new(big.Int)
		newN := fqR.Affine(utils.SetBigIntFromLEBytes(hashBigInt, hash[:]))
		// newN := fqR.Affine(leByteArrayToBigInt(hash[:]))
		res = append(res, newN)
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
func getMDS(fqR field.Fq) [][]*big.Int {
	nonce := 0
	cauchyMatrix := getPseudoRandom(fqR, SEED+"_matrix_"+nonceToString(nonce), T*2)
	for !checkAllDifferent(cauchyMatrix) {
		nonce += 1
		cauchyMatrix = getPseudoRandom(fqR, SEED+"_matrix_"+nonceToString(nonce), T*2)
	}
	var m [][]*big.Int
	for i := 0; i < T; i++ {
		var mi []*big.Int
		for j := 0; j < T; j++ {
			mi = append(mi, fqR.Inverse(fqR.Sub(cauchyMatrix[i], cauchyMatrix[T+j])))
		}
		m = append(m, mi)
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
func ark(state []*big.Int, c *big.Int) []*big.Int {
	for i := 0; i < T; i++ {
		state[i] = constants.fqR.Add(state[i], c)
	}
	return state
}

// cubic performs x^5 mod p
// https://eprint.iacr.org/2019/458.pdf page 8
func cubic(a *big.Int) *big.Int {
	return constants.fqR.Mul(a, constants.fqR.Square(constants.fqR.Square(a)))
}

// sbox https://eprint.iacr.org/2019/458.pdf page 6
func sbox(state []*big.Int, i int) []*big.Int {
	if (i < NROUNDSF/2) || (i >= NROUNDSF/2+NROUNDSP) {
		for j := 0; j < T; j++ {
			state[j] = cubic(state[j])
		}
	} else {
		state[0] = cubic(state[0])
	}
	return state
}

// mix returns [[matrix]] * [vector]
func mix(state []*big.Int, m [][]*big.Int) []*big.Int {
	var newState []*big.Int
	for i := 0; i < len(state); i++ {
		newState = append(newState, constants.fqR.Zero())
		for j := 0; j < len(state); j++ {
			newState[i] = constants.fqR.Add(newState[i], constants.fqR.Mul(m[i][j], state[j]))
		}
	}
	return newState
}

// PoseidonHash computes the Poseidon hash for the given inputs
func PoseidonHash(inp []*big.Int) (*big.Int, error) {
	if len(inp) == 0 || len(inp) > T {
		return nil, errors.New("wrong inputs length")
	}
	if !utils.CheckBigIntArrayInField(inp, constants.fqR.Q) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	state := inp
	for i := len(inp); i < T; i++ {
		state = append(state, constants.fqR.Zero())
	}

	// ARK --> SBox --> M, https://eprint.iacr.org/2019/458.pdf pag.5
	for i := 0; i < NROUNDSF+NROUNDSP; i++ {
		state = ark(state, constants.c[i])
		state = sbox(state, i)
		state = mix(state, constants.m)
	}
	return state[0], nil
}

// Hash performs the Poseidon hash over a *big.Int array
// in chunks of 5 elements
func Hash(arr []*big.Int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(arr, constants.fqR.Q) {
		return nil, errors.New("inputs values not inside Finite Field")
	}

	r := constants.fqR.Zero()
	for i := 0; i < len(arr); i = i + T - 1 {
		var toHash [T]*big.Int
		for j := 0; j < T-1; j++ {
			if i+j < len(arr) {
				toHash[j] = arr[i+j]
			} else {
				toHash[j] = _constants.Zero
			}
		}
		toHash[T-1] = r
		ph, err := PoseidonHash(toHash[:])
		if err != nil {
			return nil, err
		}
		r = constants.fqR.Add(
			r,
			ph)
	}

	return r, nil
}

// HashBytes hashes a msg byte slice by blocks of 31 bytes encoded as
// little-endian
func HashBytes(b []byte) (*big.Int, error) {
	n := 31
	bElems := make([]*big.Int, 0, len(b)/n+1)
	for i := 0; i < len(b)/n; i++ {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, b[n*i:n*(i+1)])
		bElems = append(bElems, v)
	}
	if len(b)%n != 0 {
		v := new(big.Int)
		utils.SetBigIntFromLEBytes(v, b[(len(b)/n)*n:])
		bElems = append(bElems, v)
	}
	return Hash(bElems)
}
