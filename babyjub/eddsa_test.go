package babyjub

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/stretchr/testify/assert"

	"math/big"
	"testing"
)

func genInputs() (*PrivateKey, *big.Int) {
	k := NewRandPrivKey()
	fmt.Println("k", hex.EncodeToString(k[:]))

	msgBuf := [32]byte{}
	rand.Read(msgBuf[:])
	msg := SetBigIntFromLEBytes(new(big.Int), msgBuf[:])
	msg.Mod(msg, Q)
	fmt.Println("msg", msg)

	return &k, msg
}

func TestSignVerify1(t *testing.T) {
	var k PrivateKey
	hex.Decode(k[:], []byte("0001020304050607080900010203040506070809000102030405060708090001"))
	msgBuf, err := hex.DecodeString("00010203040506070809")
	if err != nil {
		panic(err)
	}
	msg := SetBigIntFromLEBytes(new(big.Int), msgBuf)

	pk := k.Public()
	assert.Equal(t,
		"2610057752638682202795145288373380503107623443963127956230801721756904484787",
		pk.X.String())
	assert.Equal(t,
		"16617171478497210597712478520507818259149717466230047843969353176573634386897",
		pk.Y.String())

	sig := k.SignMimc7(msg)
	assert.Equal(t,
		"4974729414807584049518234760796200867685098748448054182902488636762478901554",
		sig.R8.X.String())
	assert.Equal(t,
		"18714049394522540751536514815950425694461287643205706667341348804546050128733",
		sig.R8.Y.String())
	assert.Equal(t,
		"2171284143457722024136077617757713039502332290425057126942676527240038689549",
		sig.S.String())

	ok := pk.VerifyMimc7(msg, sig)
	assert.Equal(t, true, ok)

	sigBuf := sig.Compress()
	sig2, err := new(Signature).Decompress(sigBuf)
	assert.Equal(t, nil, err)

	assert.Equal(t, ""+
		"5dfb6f843c023fe3e52548ccf22e55c81b426f7af81b4f51f7152f2fcfc65f29"+
		"0dab19c5a0a75973cd75a54780de0c3a41ede6f57396fe99b5307fff3ce7cc04",
		hex.EncodeToString(sigBuf[:]))

	ok = pk.VerifyMimc7(msg, sig2)
	assert.Equal(t, true, ok)
}

func TestCompressDecompress(t *testing.T) {
	var k PrivateKey
	hex.Decode(k[:], []byte("0001020304050607080900010203040506070809000102030405060708090001"))
	pk := k.Public()
	for i := 0; i < 64; i++ {
		msgBuf, err := hex.DecodeString(fmt.Sprintf("000102030405060708%02d", i))
		if err != nil {
			panic(err)
		}
		msg := SetBigIntFromLEBytes(new(big.Int), msgBuf)
		sig := k.SignMimc7(msg)
		sigBuf := sig.Compress()
		sig2, err := new(Signature).Decompress(sigBuf)
		assert.Equal(t, nil, err)
		ok := pk.VerifyMimc7(msg, sig2)
		assert.Equal(t, true, ok)
	}
}
