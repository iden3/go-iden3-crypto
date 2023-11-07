package mimc7

import (
	"errors"
	"math/big"

	_constants "github.com/iden3/go-iden3-crypto/v2/constants"
	"github.com/iden3/go-iden3-crypto/v2/ff"
	"github.com/iden3/go-iden3-crypto/v2/keccak256"
	"github.com/iden3/go-iden3-crypto/v2/utils"
)

// SEED defines the seed used to constants
const SEED = "mimc"

var constants = generateConstantsData()

type constantsData struct {
	seedHash *big.Int
	iv       *big.Int
	nRounds  int
	cts      []*ff.Element
}

func generateConstantsData() constantsData {
	var consts constantsData

	consts.seedHash = new(big.Int).SetBytes(keccak256.Hash([]byte(SEED)))
	c := new(big.Int).SetBytes(keccak256.Hash([]byte(SEED + "_iv")))
	consts.iv = new(big.Int).Mod(c, _constants.Q)

	consts.nRounds = 91
	cts := getConstants(SEED, consts.nRounds)
	consts.cts = cts
	return consts
}

func getConstants(seed string, nRounds int) []*ff.Element {
	cts := make([]*ff.Element, nRounds)
	cts[0] = new(ff.Element)
	c := new(big.Int).SetBytes(keccak256.Hash([]byte(seed)))
	for i := 1; i < nRounds; i++ {
		c = new(big.Int).SetBytes(keccak256.Hash(c.Bytes()))

		n := new(big.Int).Mod(c, _constants.Q)
		cts[i] = new(ff.Element).SetBigInt(n)
	}
	return cts
}

// MIMC7HashGeneric performs the MIMC7 hash over a *big.Int, in a generic way,
// where it can be specified the Finite Field over R, and the number of rounds
func MIMC7HashGeneric(xInBI, kBI *big.Int, nRounds int) *big.Int { //nolint:golint
	xIn := new(ff.Element).SetBigInt(xInBI)
	k := new(ff.Element).SetBigInt(kBI)

	cts := getConstants(SEED, nRounds)
	var r *ff.Element
	for i := 0; i < nRounds; i++ {
		var t *ff.Element
		if i == 0 {
			t = new(ff.Element).Add(xIn, k)
		} else {
			t = new(ff.Element).Add(new(ff.Element).Add(r, k), cts[i])
		}
		t2 := new(ff.Element).Square(t)
		t4 := new(ff.Element).Square(t2)
		r = new(ff.Element).Mul(new(ff.Element).Mul(t4, t2), t)
	}
	rE := new(ff.Element).Add(r, k)

	res := big.NewInt(0)
	rE.BigInt(res)
	return res
}

// HashGeneric performs the MIMC7 hash over a *big.Int array, in a generic way,
// where it can be specified the Finite Field over R, and the number of rounds
func HashGeneric(iv *big.Int, arr []*big.Int, nRounds int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(arr) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	r := iv
	var err error
	for i := 0; i < len(arr); i++ {
		r = MIMC7HashGeneric(r, arr[i], nRounds)
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

// MIMC7Hash performs the MIMC7 hash over a *big.Int, using the Finite Field
// over R and the number of rounds setted in the `constants` variable
func MIMC7Hash(xInBI, kBI *big.Int) *big.Int { //nolint:golint
	xIn := new(ff.Element).SetBigInt(xInBI)
	k := new(ff.Element).SetBigInt(kBI)

	var r *ff.Element
	for i := 0; i < constants.nRounds; i++ {
		var t *ff.Element
		if i == 0 {
			t = new(ff.Element).Add(xIn, k)
		} else {
			t = new(ff.Element).Add(new(ff.Element).Add(r, k), constants.cts[i])
		}
		t2 := new(ff.Element).Square(t)
		t4 := new(ff.Element).Square(t2)
		r = new(ff.Element).Mul(new(ff.Element).Mul(t4, t2), t)
	}
	rE := new(ff.Element).Add(r, k)

	res := big.NewInt(0)
	rE.BigInt(res)
	return res
}

// Hash performs the MIMC7 hash over a *big.Int array
func Hash(arr []*big.Int, key *big.Int) (*big.Int, error) {
	if !utils.CheckBigIntArrayInField(arr) {
		return nil, errors.New("inputs values not inside Finite Field")
	}
	var r *big.Int
	if key == nil {
		r = big.NewInt(0)
	} else {
		r = key
	}
	for i := 0; i < len(arr); i++ {
		r = new(big.Int).Add(
			new(big.Int).Add(
				r,
				arr[i],
			),
			MIMC7Hash(arr[i], r))
		r = new(big.Int).Mod(r, _constants.Q)
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
	h, err := Hash(bElems, nil)
	if err != nil {
		return nil, err
	}
	return h, nil
}
