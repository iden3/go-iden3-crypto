package babyjub

import (
	"crypto"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/babyjub"
	poseidon "github.com/iden3/go-iden3-crypto/poseidon/wrapper"
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
	require.Implements(t, (*crypto.Signer)(nil), new(PrivateKey))
	require.Implements(t, (*shadowPrivateKey)(nil), new(PrivateKey))
}

func TestBjjWrappedPrivateKey(t *testing.T) {
	pk := NewRandPrivKey()

	hasher := poseidon.New()
	hasher.Write([]byte("test"))
	digest := hasher.Sum(nil)

	sig, err := pk.Sign(rand.Reader, digest, crypto.Hash(0))
	require.NoError(t, err)
	pub, ok := pk.Public().(*PublicKey)
	require.True(t, ok)

	decomrpessSig, err := decomrpessSig(sig)
	require.NoError(t, err)

	digestBI := big.NewInt(0).SetBytes(digest)
	pub.pubKey.VerifyPoseidon(digestBI, decomrpessSig)
}

func TestBjjWrappedPrivateKeyEqual(t *testing.T) {
	x1 := NewRandPrivKey()
	require.True(t, x1.Equal(x1))
	x2 := NewRandPrivKey()
	require.False(t, x1.Equal(x2))
}

func TestBjjWrappedPublicKeyInterfaceImpl(t *testing.T) {
	require.Implements(t, (*shadowPublicKey)(nil), new(PublicKey))
}

func TestBjjWrappedPublicKeyEqual(t *testing.T) {
	x1 := NewRandPrivKey().Public().(*PublicKey)
	require.True(t, x1.Equal(x1))
	x2 := NewRandPrivKey().Public()
	require.False(t, x1.Equal(x2))
}

func decomrpessSig(commpresedSig []byte) (*babyjub.Signature, error) {
	poseidonComSig := &babyjub.SignatureComp{}
	if err := poseidonComSig.UnmarshalText(commpresedSig); err != nil {
		return nil, err
	}
	poseidonDecSig, err := poseidonComSig.Decompress()
	if err != nil {
		return nil, err
	}
	return poseidonDecSig, nil
}
