package babyjub

import (
	"crypto/rand"
	// "encoding/hex"
	// "fmt"
	common3 "github.com/iden3/go-iden3/common"
	"github.com/iden3/go-iden3/crypto/mimc7"
	// "golang.org/x/crypto/blake2b"
	"math/big"
)

// pruneBuffer prunes the buffer during key generation according to RFC 8032.
// https://tools.ietf.org/html/rfc8032#page-13
func pruneBuffer(buf *[32]byte) *[32]byte {
	buf[0] = buf[0] & 0xF8
	buf[31] = buf[31] & 0x7F
	buf[31] = buf[31] | 0x40
	return buf
}

// PrivateKey is an EdDSA private key, which is a 32byte buffer.
type PrivateKey [32]byte

// NewRandPrivKey generates a new random private key (using cryptographically
// secure randomness).
func NewRandPrivKey() PrivateKey {
	var k PrivateKey
	_, err := rand.Read(k[:])
	if err != nil {
		panic(err)
	}
	return k
}

// Scalar converts a private key into the scalar value s following the EdDSA
// standard, and using blake-512 hash.
func (k *PrivateKey) Scalar() *PrivKeyScalar {
	sBuf := Blake512(k[:])
	sBuf32 := [32]byte{}
	copy(sBuf32[:], sBuf[:32])
	pruneBuffer(&sBuf32)
	s := new(big.Int)
	SetBigIntFromLEBytes(s, sBuf32[:])
	s.Rsh(s, 3)
	return NewPrivKeyScalar(s)
}

// Pub returns the public key corresponding to a private key.
func (k *PrivateKey) Public() *PublicKey {
	return k.Scalar().Public()
}

// PrivKeyScalar represents the scalar s output of a private key
type PrivKeyScalar big.Int

// NewPrivKeyScalar creates a new PrivKeyScalar from a big.Int
func NewPrivKeyScalar(s *big.Int) *PrivKeyScalar {
	sk := PrivKeyScalar(*s)
	return &sk
}

// Pub returns the public key corresponding to the scalar value s of a private
// key.
func (s *PrivKeyScalar) Public() *PublicKey {
	p := NewPoint().Mul((*big.Int)(s), B8)
	pk := PublicKey(*p)
	return &pk
}

// BigInt returns the big.Int corresponding to a PrivKeyScalar.
func (s *PrivKeyScalar) BigInt() *big.Int {
	return (*big.Int)(s)
}

// PublicKey represents an EdDSA public key, which is a curve point.
type PublicKey Point

func (pk PublicKey) MarshalText() ([]byte, error) {
	pkc := pk.Compress()
	return common3.Hex(pkc[:]).MarshalText()
}

func (pk PublicKey) String() string {
	pkc := pk.Compress()
	return common3.Hex(pkc[:]).String()
}

func (pk *PublicKey) UnmarshalText(h []byte) error {
	var pkc PublicKeyComp
	if err := common3.HexDecodeInto(pkc[:], h); err != nil {
		return err
	}
	pkd, err := pkc.Decompress()
	if err != nil {
		return err
	}
	*pk = *pkd
	return nil
}

// Point returns the Point corresponding to a PublicKey.
func (p *PublicKey) Point() *Point {
	return (*Point)(p)
}

// PublicKeyComp represents a compressed EdDSA Public key; it's a compressed curve
// point.
type PublicKeyComp [32]byte

func (buf PublicKeyComp) MarshalText() ([]byte, error)  { return common3.Hex(buf[:]).MarshalText() }
func (buf PublicKeyComp) String() string                { return common3.Hex(buf[:]).String() }
func (buf *PublicKeyComp) UnmarshalText(h []byte) error { return common3.HexDecodeInto(buf[:], h) }

func (p *PublicKey) Compress() PublicKeyComp {
	return PublicKeyComp((*Point)(p).Compress())
}

func (p *PublicKeyComp) Decompress() (*PublicKey, error) {
	point, err := NewPoint().Decompress(*p)
	if err != nil {
		return nil, err
	}
	pk := PublicKey(*point)
	return &pk, nil
}

// Signature represents an EdDSA uncompressed signature.
type Signature struct {
	R8 *Point
	S  *big.Int
}

// SignatureComp represents a compressed EdDSA signature.
type SignatureComp [64]byte

func (buf SignatureComp) MarshalText() ([]byte, error)  { return common3.Hex(buf[:]).MarshalText() }
func (buf SignatureComp) String() string                { return common3.Hex(buf[:]).String() }
func (buf *SignatureComp) UnmarshalText(h []byte) error { return common3.HexDecodeInto(buf[:], h) }

// Compress an EdDSA signature by concatenating the compression of
// the point R8 and the Little-Endian encoding of S.
func (s *Signature) Compress() SignatureComp {
	R8p := s.R8.Compress()
	Sp := BigIntLEBytes(s.S)
	buf := [64]byte{}
	copy(buf[:32], R8p[:])
	copy(buf[32:], Sp[:])
	return SignatureComp(buf)
}

// Decompress a compressed signature into s, and also returns the decompressed
// signature.  Returns error if the Point decompression fails.
func (s *Signature) Decompress(buf [64]byte) (*Signature, error) {
	R8p := [32]byte{}
	copy(R8p[:], buf[:32])
	var err error
	if s.R8, err = NewPoint().Decompress(R8p); err != nil {
		return nil, err
	}
	s.S = SetBigIntFromLEBytes(new(big.Int), buf[32:])
	return s, nil
}

// Decompress a compressed signature.  Returns error if the Point decompression
// fails.
func (s *SignatureComp) Decompress() (*Signature, error) {
	return new(Signature).Decompress(*s)
}

// SignMimc7 signs a message encoded as a big.Int in Zq using blake-512 hash
// for buffer hashing and mimc7 for big.Int hashing.
func (k *PrivateKey) SignMimc7(msg *big.Int) *Signature {
	h1 := Blake512(k[:])
	msgBuf := BigIntLEBytes(msg)
	msgBuf32 := [32]byte{}
	copy(msgBuf32[:], msgBuf[:])
	rBuf := Blake512(append(h1[32:], msgBuf32[:]...))
	r := SetBigIntFromLEBytes(new(big.Int), rBuf) // r = H(H_{32..63}(k), msg)
	r.Mod(r, SubOrder)
	R8 := NewPoint().Mul(r, B8) // R8 = r * 8 * B
	A := k.Public().Point()
	hmInput, err := mimc7.BigIntsToRElems([]*big.Int{R8.X, R8.Y, A.X, A.Y, msg})
	if err != nil {
		panic(err)
	}
	hm := mimc7.Hash(hmInput, nil) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	S := new(big.Int).Lsh(k.Scalar().BigInt(), 3)
	S = S.Mul(hm, S)
	S.Add(r, S)
	S.Mod(S, SubOrder) // S = r + hm * 8 * s

	return &Signature{R8: R8, S: S}
}

// VerifyMimc7 verifies the signature of a message encoded as a big.Int in Zq
// using blake-512 hash for buffer hashing and mimc7 for big.Int hashing.
func (p *PublicKey) VerifyMimc7(msg *big.Int, sig *Signature) bool {
	hmInput, err := mimc7.BigIntsToRElems([]*big.Int{sig.R8.X, sig.R8.Y, p.X, p.Y, msg})
	if err != nil {
		panic(err)
	}
	hm := mimc7.Hash(hmInput, nil) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)

	left := NewPoint().Mul(sig.S, B8) // left = s * 8 * B
	r1 := big.NewInt(8)
	r1.Mul(r1, hm)
	right := NewPoint().Mul(r1, p.Point())
	right.Add(sig.R8, right) // right = 8 * R + 8 * hm * A
	return (left.X.Cmp(right.X) == 0) && (left.Y.Cmp(right.Y) == 0)
}
