package babyjub

import (
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/v2/constants"
	"github.com/iden3/go-iden3-crypto/v2/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKey(t *testing.T) {
	var k PrivateKey
	for i := 0; i < 32; i++ {
		k[i] = byte(i)
	}
	pk := k.Public()
	assert.True(t, pk.X.Cmp(constants.Q) == -1)
	assert.True(t, pk.Y.Cmp(constants.Q) == -1)
}

func TestSignVerifyMimc7(t *testing.T) {
	var k PrivateKey
	_, err := hex.Decode(k[:],
		[]byte("0001020304050607080900010203040506070809000102030405060708090001"))
	require.NoError(t, err)
	msgBuf, err := hex.DecodeString("00010203040506070809")
	require.NoError(t, err)
	msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf)

	pk := k.Public()
	assert.Equal(t,
		"13277427435165878497778222415993513565335242147425444199013288855685581939618",
		pk.X.String())
	assert.Equal(t,
		"13622229784656158136036771217484571176836296686641868549125388198837476602820",
		pk.Y.String())

	sig, err := k.SignMimc7(msg)
	require.NoError(t, err)
	assert.Equal(t,
		"11384336176656855268977457483345535180380036354188103142384839473266348197733",
		sig.R8.X.String())
	assert.Equal(t,
		"15383486972088797283337779941324724402501462225528836549661220478783371668959",
		sig.R8.Y.String())
	assert.Equal(t,
		"2523202440825208709475937830811065542425109372212752003460238913256192595070",
		sig.S.String())

	err = pk.VerifyMimc7(msg, sig)
	require.NoError(t, err)

	sigBuf := sig.Compress()
	sig2, err := new(Signature).Decompress(sigBuf)
	require.NoError(t, err)

	assert.Equal(t, ""+
		"dfedb4315d3f2eb4de2d3c510d7a987dcab67089c8ace06308827bf5bcbe02a2"+
		"7ed40dab29bf993c928e789d007387998901a24913d44fddb64b1f21fc149405",
		hex.EncodeToString(sigBuf[:]))

	err = pk.VerifyMimc7(msg, sig2)
	require.NoError(t, err)
}

func TestSignVerifyPoseidon(t *testing.T) {
	var k PrivateKey
	_, err := hex.Decode(k[:],
		[]byte("0001020304050607080900010203040506070809000102030405060708090001"))
	require.NoError(t, err)
	msgBuf, err := hex.DecodeString("00010203040506070809")
	require.NoError(t, err)
	msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf)

	pk := k.Public()
	assert.Equal(t,
		"13277427435165878497778222415993513565335242147425444199013288855685581939618",
		pk.X.String())
	assert.Equal(t,
		"13622229784656158136036771217484571176836296686641868549125388198837476602820",
		pk.Y.String())

	sig, err := k.SignPoseidon(msg)
	require.NoError(t, err)
	assert.Equal(t,
		"11384336176656855268977457483345535180380036354188103142384839473266348197733",
		sig.R8.X.String())
	assert.Equal(t,
		"15383486972088797283337779941324724402501462225528836549661220478783371668959",
		sig.R8.Y.String())
	assert.Equal(t,
		"1672775540645840396591609181675628451599263765380031905495115170613215233181",
		sig.S.String())

	err = pk.VerifyPoseidon(msg, sig)
	require.NoError(t, err)

	sigBuf := sig.Compress()
	sig2, err := new(Signature).Decompress(sigBuf)
	require.NoError(t, err)

	assert.Equal(t, ""+
		"dfedb4315d3f2eb4de2d3c510d7a987dcab67089c8ace06308827bf5bcbe02a2"+
		"9d043ece562a8f82bfc0adb640c0107a7d3a27c1c7c1a6179a0da73de5c1b203",
		hex.EncodeToString(sigBuf[:]))

	err = pk.VerifyPoseidon(msg, sig2)
	require.NoError(t, err)
}

func TestCompressDecompress(t *testing.T) {
	var k PrivateKey
	_, err := hex.Decode(k[:],
		[]byte("0001020304050607080900010203040506070809000102030405060708090001"))
	require.NoError(t, err)
	pk := k.Public()
	for i := 0; i < 64; i++ {
		msgBuf, err := hex.DecodeString(fmt.Sprintf("000102030405060708%02d", i))
		require.NoError(t, err)
		msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf)
		sig, err := k.SignMimc7(msg)
		require.NoError(t, err)
		sigBuf := sig.Compress()
		sig2, err := new(Signature).Decompress(sigBuf)
		require.NoError(t, err)
		err = pk.VerifyMimc7(msg, sig2)
		require.NoError(t, err)
	}
}

func TestSignatureCompScannerValuer(t *testing.T) {
	privK, _ := NewRandPrivKey()
	var err error
	sig, err := privK.SignPoseidon(big.NewInt(674238462))
	require.NoError(t, err)
	var value driver.Valuer //nolint:gosimple // this is done to ensure interface compatibility
	value = sig.Compress()
	sig, err = privK.SignPoseidon(big.NewInt(1))
	require.NoError(t, err)
	scan := sig.Compress()
	fromDB, err := value.Value()
	require.NoError(t, err)
	assert.Nil(t, scan.Scan(fromDB))
	assert.Equal(t, value, scan)
}

func TestSignatureScannerValuer(t *testing.T) {
	privK, _ := NewRandPrivKey()
	var value driver.Valuer
	var scan sql.Scanner
	var err error
	value, err = privK.SignPoseidon(big.NewInt(674238462))
	require.NoError(t, err)
	scan, err = privK.SignPoseidon(big.NewInt(1))
	require.NoError(t, err)
	fromDB, err := value.Value()
	require.NoError(t, err)
	assert.Nil(t, scan.Scan(fromDB))
	assert.Equal(t, value, scan)
}

func TestPublicKeyScannerValuer(t *testing.T) {
	privKValue, _ := NewRandPrivKey()
	pubKValue := privKValue.Public()
	privKScan, _ := NewRandPrivKey()
	pubKScan := privKScan.Public()
	var value driver.Valuer
	var scan sql.Scanner
	value = pubKValue
	scan = pubKScan
	fromDB, err := value.Value()
	require.NoError(t, err)
	assert.Nil(t, scan.Scan(fromDB))
	assert.Equal(t, value, scan)
}

func TestPublicKeyCompScannerValuer(t *testing.T) {
	privKValue, _ := NewRandPrivKey()
	pubKCompValue := privKValue.Public().Compress()
	privKScan, _ := NewRandPrivKey()
	pubKCompScan := privKScan.Public().Compress()
	var value driver.Valuer
	var scan sql.Scanner
	value = &pubKCompValue
	scan = &pubKCompScan
	fromDB, err := value.Value()
	require.NoError(t, err)
	assert.Nil(t, scan.Scan(fromDB))
	assert.Equal(t, value, scan)
}

func BenchmarkBabyjubEddsa(b *testing.B) {
	var k PrivateKey
	_, err := hex.Decode(k[:],
		[]byte("0001020304050607080900010203040506070809000102030405060708090001"))
	require.NoError(b, err)
	pk := k.Public()

	const n = 256

	msgBuf, err := hex.DecodeString("00010203040506070809")
	require.NoError(b, err)
	msg := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf)
	var msgs [n]*big.Int
	for i := 0; i < n; i++ {
		msgs[i] = new(big.Int).Add(msg, big.NewInt(int64(i)))
	}
	var sigs [n]*Signature

	b.Run("SignMimc7", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = k.SignMimc7(msgs[i%n])
			require.NoError(b, err)
		}
	})

	for i := 0; i < n; i++ {
		sigs[i%n], err = k.SignMimc7(msgs[i%n])
		require.NoError(b, err)
	}

	b.Run("VerifyMimc7", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = pk.VerifyMimc7(msgs[i%n], sigs[i%n])
			require.NoError(b, err)
		}
	})

	b.Run("SignPoseidon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = k.SignPoseidon(msgs[i%n])
			require.NoError(b, err)
		}
	})

	for i := 0; i < n; i++ {
		sigs[i%n], err = k.SignPoseidon(msgs[i%n])
		require.NoError(b, err)
	}

	b.Run("VerifyPoseidon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = pk.VerifyPoseidon(msgs[i%n], sigs[i%n])
			require.NoError(b, err)
		}
	})
}
