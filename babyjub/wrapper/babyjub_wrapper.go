// This package is a wrapper for babyjub package.
// It is used to implement the standart golang inerfaces like
// crypto.Signer, crypto.PublicKey and crypto.PrivateKey.

package babyjub

import (
	"bytes"
	"crypto"
	"io"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
)

// PublicKey is a wrapper for babyjub.PublicKey.
type PublicKey struct {
	pubKey *babyjub.PublicKey
}

// Equal returns true if the public keys are equal.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	var xk *PublicKey
	switch x := x.(type) {
	case PublicKey:
		xk = &x
	case *PublicKey:
		xk = x
	default:
		return false
	}
	return pub.pubKey.X.Cmp(xk.pubKey.X) == 0 &&
		pub.pubKey.Y.Cmp(xk.pubKey.Y) == 0
}

// PrivateKey is a wrapper for babyjub.PrivateKey.
type PrivateKey struct {
	privKey *babyjub.PrivateKey
}

// NewPrivateKey creates a new PrivateKey.
func NewPrivateKey(privKey *babyjub.PrivateKey) *PrivateKey {
	return &PrivateKey{privKey}
}

// NewRandPrivKey creates a new PrivateKey with a random babyjub private key.
func NewRandPrivKey() *PrivateKey {
	privKey := babyjub.NewRandPrivKey()
	return NewPrivateKey(&privKey)
}

// Public returns the public key of the private key.
func (w *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{w.privKey.Public()}
}

// Sign signs the digest with the private key.
func (w *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()

	switch hash {
	// alredy hashed
	case crypto.Hash(0):
	default:
		hasher := hash.New()
		hasher.Write(digest)
		digest = hasher.Sum(nil)
	}

	digestBI := big.NewInt(0).SetBytes(digest)
	sig := w.privKey.SignPoseidon(digestBI)
	return sig.Compress().MarshalText()
}

// Equal returns true if the private keys are equal.
func (w *PrivateKey) Equal(x crypto.PrivateKey) bool {
	var xk *PrivateKey
	switch x := x.(type) {
	case PrivateKey:
		xk = &x
	case *PrivateKey:
		xk = x
	default:
		return false
	}
	return bytes.Equal(w.privKey[:], xk.privKey[:])
}
