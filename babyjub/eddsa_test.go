package babyjub

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"

	"math/big"
	"testing"
)

func genInputs() (*PrivateKey, *big.Int) {
	k := NewRandPrivKey()
	fmt.Println("k", hex.EncodeToString(k[:]))

	msgBuf := [32]byte{}
	rand.Read(msgBuf[:])
	msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf[:])
	msg.Mod(msg, constants.Q)
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
	msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf)

	pk := k.Public()
	assert.Equal(t,
		"13277427435165878497778222415993513565335242147425444199013288855685581939618",
		pk.X.String())
	assert.Equal(t,
		"13622229784656158136036771217484571176836296686641868549125388198837476602820",
		pk.Y.String())

	sig := k.SignMimc7(msg)
	assert.Equal(t,
		"11384336176656855268977457483345535180380036354188103142384839473266348197733",
		sig.R8.X.String())
	assert.Equal(t,
		"15383486972088797283337779941324724402501462225528836549661220478783371668959",
		sig.R8.Y.String())
	assert.Equal(t,
		"2523202440825208709475937830811065542425109372212752003460238913256192595070",
		sig.S.String())

	ok := pk.VerifyMimc7(msg, sig)
	assert.Equal(t, true, ok)

	sigBuf := sig.Compress()
	sig2, err := new(Signature).Decompress(sigBuf)
	assert.Equal(t, nil, err)

	assert.Equal(t, ""+
		"dfedb4315d3f2eb4de2d3c510d7a987dcab67089c8ace06308827bf5bcbe02a2"+
		"7ed40dab29bf993c928e789d007387998901a24913d44fddb64b1f21fc149405",
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
		msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf)
		sig := k.SignMimc7(msg)
		sigBuf := sig.Compress()
		sig2, err := new(Signature).Decompress(sigBuf)
		assert.Equal(t, nil, err)
		ok := pk.VerifyMimc7(msg, sig2)
		assert.Equal(t, true, ok)
	}
}
