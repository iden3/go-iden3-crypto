package keccak256

import (
	"golang.org/x/crypto/sha3"
)

// Hash generates a Keccak256 hash from a byte array
func Hash(data ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, d := range data {
		hash.Write(d) //nolint:errcheck,gosec
	}
	return hash.Sum(nil)
}
