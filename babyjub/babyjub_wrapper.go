package babyjub

import (
	"bytes"
	"crypto"
	"io"
	"math/big"
)

// BjjWrappedPublicKey is a wrapper for PublicKey.
type BjjWrappedPublicKey struct {
	pubKey *PublicKey
}

// Equal returns true if the public keys are equal.
func (pub *BjjWrappedPublicKey) Equal(x crypto.PublicKey) bool {
	var xk *BjjWrappedPublicKey
	switch x := x.(type) {
	case BjjWrappedPublicKey:
		xk = &x
	case *BjjWrappedPublicKey:
		xk = x
	default:
		return false
	}
	return pub.pubKey.X.Cmp(xk.pubKey.X) == 0 &&
		pub.pubKey.Y.Cmp(xk.pubKey.Y) == 0
}

// BjjWrappedPrivateKey is a wrapper for PrivateKey.
type BjjWrappedPrivateKey struct {
	privKey *PrivateKey
}

// NewBjjWrappedKey creates a new BjjWrappedPrivateKey.
func NewBjjWrappedKey(privKey *PrivateKey) *BjjWrappedPrivateKey {
	return &BjjWrappedPrivateKey{privKey}
}

// RandomBjjWrappedKey creates a new BjjWrappedPrivateKey with a random private key.
func RandomBjjWrappedKey() *BjjWrappedPrivateKey {
	privKey := NewRandPrivKey()
	return NewBjjWrappedKey(&privKey)
}

// Public returns the public key of the private key.
func (w *BjjWrappedPrivateKey) Public() crypto.PublicKey {
	return &BjjWrappedPublicKey{w.privKey.Public()}
}

// Sign signs the digest with the private key.
func (w *BjjWrappedPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
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
func (w *BjjWrappedPrivateKey) Equal(x crypto.PrivateKey) bool {
	var xk *BjjWrappedPrivateKey
	switch x := x.(type) {
	case BjjWrappedPrivateKey:
		xk = &x
	case *BjjWrappedPrivateKey:
		xk = x
	default:
		return false
	}
	return bytes.Equal(w.privKey[:], xk.privKey[:])
}
