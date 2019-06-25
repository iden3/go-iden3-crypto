package mimc7

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-iden3/crypto/field"
)

const SEED = "mimc"

// RElem is a big.Int of maximum 253 bits
type RElem *big.Int

var constants = generateConstantsData()

type constantsData struct {
	maxFieldVal *big.Int
	seedHash    *big.Int
	iv          *big.Int
	fqR         field.Fq
	nRounds     int
	cts         []*big.Int
}

func getIV(seed string) {
}

func generateConstantsData() constantsData {
	var constants constantsData

	r, ok := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	if !ok {

	}
	fqR := field.NewFq(r)
	constants.fqR = fqR

	// maxFieldVal is the R value of the Finite Field
	constants.maxFieldVal = constants.fqR.Q

	constants.seedHash = new(big.Int).SetBytes(crypto.Keccak256([]byte(SEED)))
	c := new(big.Int).SetBytes(crypto.Keccak256([]byte(SEED + "_iv")))
	constants.iv = new(big.Int).Mod(c, constants.maxFieldVal)

	constants.nRounds = 91
	cts, err := getConstants(constants.fqR, SEED, constants.nRounds)
	if err != nil {
		panic(err)
	}
	constants.cts = cts
	return constants
}

// BigIntToRElem checks if given big.Int fits in a Field R element, and returns the RElem type
func BigIntToRElem(a *big.Int) (RElem, error) {
	if a.Cmp(constants.maxFieldVal) != -1 {
		return RElem(a), errors.New("Given big.Int don't fits in the Finite Field over R")
	}
	return RElem(a), nil
}

//BigIntsToRElems converts from array of *big.Int to array of RElem
func BigIntsToRElems(arr []*big.Int) ([]RElem, error) {
	o := make([]RElem, len(arr))
	for i, a := range arr {
		e, err := BigIntToRElem(a)
		if err != nil {
			return o, fmt.Errorf("element in position %v don't fits in Finite Field over R", i)
		}
		o[i] = e
	}
	return o, nil
}

// RElemsToBigInts converts from array of RElem to array of *big.Int
func RElemsToBigInts(arr []RElem) []*big.Int {
	o := make([]*big.Int, len(arr))
	for i, a := range arr {
		o[i] = a
	}
	return o
}

func getConstants(fqR field.Fq, seed string, nRounds int) ([]*big.Int, error) {
	cts := make([]*big.Int, nRounds)
	cts[0] = big.NewInt(int64(0))
	c := new(big.Int).SetBytes(crypto.Keccak256([]byte(SEED)))
	for i := 1; i < nRounds; i++ {
		c = new(big.Int).SetBytes(crypto.Keccak256(c.Bytes()))

		n := fqR.Affine(c)
		cts[i] = n
	}
	return cts, nil
}

// MIMC7HashGeneric performs the MIMC7 hash over a RElem, in a generic way, where it can be specified the Finite Field over R, and the number of rounds
func MIMC7HashGeneric(fqR field.Fq, xIn, k *big.Int, nRounds int) (*big.Int, error) {
	cts, err := getConstants(fqR, SEED, nRounds)
	if err != nil {
		return &big.Int{}, err
	}
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
	return fqR.Affine(fqR.Add(r, k)), nil
}

// HashGeneric performs the MIMC7 hash over a RElem array, in a generic way, where it can be specified the Finite Field over R, and the number of rounds
func HashGeneric(iv *big.Int, arrEl []RElem, fqR field.Fq, nRounds int) (RElem, error) {
	arr := RElemsToBigInts(arrEl)
	r := iv
	var err error
	for i := 0; i < len(arr); i++ {
		r, err = MIMC7HashGeneric(fqR, r, arr[i], nRounds)
		if err != nil {
			return r, err
		}
	}
	return RElem(r), nil
}

// MIMC7Hash performs the MIMC7 hash over a RElem, using the Finite Field over R and the number of rounds setted in the `constants` variable
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

// Hash performs the MIMC7 hash over a RElem array
func Hash(arrEl []RElem, key *big.Int) RElem {
	arr := RElemsToBigInts(arrEl)
	var r *big.Int
	if key == nil {
		r = constants.fqR.Zero()
	} else {
		r = key
	}
	// r := constants.iv
	for i := 0; i < len(arr); i++ {
		r = constants.fqR.Add(
			constants.fqR.Add(
				r,
				arr[i],
			),
			MIMC7Hash(arr[i], r))
	}
	return RElem(r)
}
