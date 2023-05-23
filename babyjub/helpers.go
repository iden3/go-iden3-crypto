package babyjub

import (
	"github.com/dchest/blake512"
)

// Note on dchest/blake512: This specific blake512 module is compatible with
// the version of Blake512 used at circomlib, and this module has been reviewed
// to don't be doing do anything suspicious.

// Blake512 performs the blake-512 hash over the buffer m.  Note that this is
// the original blake from the SHA3 competition and not the new blake2 version.
func Blake512(m []byte) []byte {
	h := blake512.New()
	_, err := h.Write(m)
	if err != nil {
		panic(err)
	}
	return h.Sum(nil)
}

// DecompressSig decompresses a compressed signature.
func DecompressSig(commpresedSig []byte) (*Signature, error) {
	poseidonComSig := &SignatureComp{}
	if err := poseidonComSig.UnmarshalText(commpresedSig); err != nil {
		return nil, err
	}
	poseidonDecSig, err := poseidonComSig.Decompress()
	if err != nil {
		return nil, err
	}
	return poseidonDecSig, nil
}
