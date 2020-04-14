package babyjub

import (
	"github.com/dchest/blake512" // I have personally reviewed that this module doesn't do anything suspicious
)

// Blake512 performs the blake-512 hash over the buffer m.  Note that this is
// the original blake from the SHA3 competition and not the new blake2 version.
func Blake512(m []byte) []byte {
	h := blake512.New()
	_, err := h.Write(m[:])
	if err != nil {
		panic(err)
	}
	return h.Sum(nil)
}
