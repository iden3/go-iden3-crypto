package babyjub

import (
	"crypto"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

// https://pkg.go.dev/crypto#PrivateKey
type shadowPrivateKey interface {
	Public() crypto.PublicKey
	Equal(x crypto.PrivateKey) bool
}

// https://pkg.go.dev/crypto#PublicKey
type shadowPublicKey interface {
	Equal(x crypto.PublicKey) bool
}

func TestBjjWrappedPrivateKeyInterfaceImpl(t *testing.T) {
	require.Implements(t, (*crypto.Signer)(nil), new(BjjWrappedPrivateKey))
	require.Implements(t, (*shadowPrivateKey)(nil), new(BjjWrappedPrivateKey))
}

func TestBjjWrappedPrivateKey(t *testing.T) {
	pk, _ := RandomBjjWrappedKey()

	hasher, err := poseidon.New(16)
	require.NoError(t, err)
	hasher.Write([]byte("test"))
	digest := hasher.Sum(nil)

	sig, err := pk.Sign(rand.Reader, digest, crypto.Hash(0))
	require.NoError(t, err)
	pub, ok := pk.Public().(*BjjWrappedPublicKey)
	require.True(t, ok)

	decomrpessSig, err := DecompressSig(sig)
	require.NoError(t, err)

	digestBI := big.NewInt(0).SetBytes(digest)
	err = pub.pubKey.VerifyPoseidon(digestBI, decomrpessSig)
	require.NoError(t, err)
}

func TestBjjWrappedPrivateKeyEqual(t *testing.T) {
	x1, _ := RandomBjjWrappedKey()
	require.True(t, x1.Equal(x1))
	x2, _ := RandomBjjWrappedKey()
	require.False(t, x1.Equal(x2))
}

func TestBjjWrappedPublicKeyInterfaceImpl(t *testing.T) {
	require.Implements(t, (*shadowPublicKey)(nil), new(BjjWrappedPublicKey))
}

func TestBjjWrappedPublicKeyEqual(t *testing.T) {
	x1, _ := RandomBjjWrappedKey()
	x1pub := x1.Public().(*BjjWrappedPublicKey)
	require.True(t, x1pub.Equal(x1pub))
	require.True(t, x1pub.Equal(x1.Public()))
	x2, _ := RandomBjjWrappedKey()
	x2pub := x2.Public()
	require.False(t, x1pub.Equal(x2pub))
}
