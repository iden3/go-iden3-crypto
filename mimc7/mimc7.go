package mimc7

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	_constants "github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/field"
	"github.com/iden3/go-iden3-crypto/utils"
)

const SEED = "mimc"

var constants = generateConstantsData()

type constantsData struct {
	maxFieldVal *big.Int
	seedHash    *big.Int
	iv          *big.Int
	fqR         field.Fq
	nRounds     int
	cts         []*big.Int
}

func generateConstantsData() constantsData {
	var constants constantsData

	fqR := field.NewFq(_constants.Q)
	constants.fqR = fqR

	// maxFieldVal is the R value of the Finite Field
	constants.maxFieldVal = constants.fqR.Q

	constants.seedHash = new(big.Int).SetBytes(crypto.Keccak256([]byte(SEED)))
	c := new(big.Int).SetBytes(crypto.Keccak256([]byte(SEED + "_iv")))
	constants.iv = new(big.Int).Mod(c, constants.maxFieldVal)

	constants.nRounds = 91
	cts := getConstants(constants.fqR, SEED, constants.nRounds)
	constants.cts = cts
	return constants
}

func getConstants(fqR field.Fq, seed string, nRounds int) []*big.Int {
	cts := make([]*big.Int, nRounds)
	cts[0] = big.NewInt(int64(0))
	c := new(big.Int).SetBytes(crypto.Keccak256([]byte(SEED)))
	for i := 1; i < nRounds; i++ {
		c = new(big.Int).SetBytes(crypto.Keccak256(c.Bytes()))

		n := fqR.Affine(c)
		cts[i] = n
	}
	return cts
}

// MIMC7HashGeneric performs the MIMC7 hash over a *big.Int, in a generic way, where it can be specified the Finite Field over R, and the number of rounds
func MIMC7HashGeneric(fqR field.Fq, xIn, k *big.Int, nRounds int) *big.Int {
	cts := getConstants(fqR, SEED, nRounds)
	var r *big.Int
	for i := 0; i < nRounds; i++ {
		var t *big.Int
		if i == 0 {
			t = fqR.Add(xIn, k)
		} else {
			t = fqR.Add(fqR.Add(r, k), cts[i])
		}
		t2 := fqR.Square(t)
		t4 := fqR.Square(t2)
		r = fqR.Mul(fqR.Mul(t4, t2), t)
	}
	return fqR.Affine(fqR.Add(r, k))
}

// HashGeneric performs the MIMC7 hash over a *big.Int array, in a generic way, where it can be specified the Finite Field over R, and the number of rounds
func HashGeneric(iv *big.Int, arr []*big.Int, fqR field.Fq, nRounds int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(arr) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	r := iv
	var err error
	for i := 0; i < len(arr); i++ {
		r = MIMC7HashGeneric(fqR, r, arr[i], nRounds)
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

// MIMC7Hash performs the MIMC7 hash over a *big.Int, using the Finite Field over R and the number of rounds setted in the `constants` variable
func MIMC7Hash(xIn, k *big.Int) *big.Int {
	var r *big.Int
	for i := 0; i < constants.nRounds; i++ {
		var t *big.Int
		if i == 0 {
			t = constants.fqR.Add(xIn, k)
		} else {
			t = constants.fqR.Add(constants.fqR.Add(r, k), constants.cts[i])
		}
		t2 := constants.fqR.Square(t)
		t4 := constants.fqR.Square(t2)
		r = constants.fqR.Mul(constants.fqR.Mul(t4, t2), t)
	}
	return constants.fqR.Affine(constants.fqR.Add(r, k))
}

// Hash performs the MIMC7 hash over a *big.Int array
func Hash(arr []*big.Int, key *big.Int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(arr) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	var r *big.Int
	if key == nil {
		r = constants.fqR.Zero()
	} else {
		r = key
	}
	for i := 0; i < len(arr); i++ {
		r = constants.fqR.Add(
			constants.fqR.Add(
				r,
				arr[i],
			),
			MIMC7Hash(arr[i], r))
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
	return Hash(bElems, nil)
}
