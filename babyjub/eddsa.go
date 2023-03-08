// Package babyjub eddsa implements the EdDSA over the BabyJubJub curve
//
//nolint:gomnd
package babyjub

import (
	"crypto/rand"
	"database/sql/driver"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-iden3-crypto/utils"
)

// pruneBuffer prunes the buffer during key generation according to RFC 8032.
// https://tools.ietf.org/html/rfc8032#page-13
func pruneBuffer(buf *[32]byte) *[32]byte {
	buf[0] &= 0xF8
	buf[31] &= 0x7F
	buf[31] |= 0x40
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
	s := SkToBigInt(k)
	return NewPrivKeyScalar(s)
}

// SkToBigInt converts a private key into the *big.Int value following the
// EdDSA standard, and using blake-512 hash
func SkToBigInt(k *PrivateKey) *big.Int {
	sBuf := Blake512(k[:])
	sBuf32 := [32]byte{}
	copy(sBuf32[:], sBuf[:32])
	pruneBuffer(&sBuf32)
	s := new(big.Int)
	utils.SetBigIntFromLEBytes(s, sBuf32[:])
	s.Rsh(s, 3)
	return s
}

// Public returns the public key corresponding to a private key.
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

// Public returns the public key corresponding to the scalar value s of a
// private key.
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

// MarshalText implements the marshaler for PublicKey
func (pk PublicKey) MarshalText() ([]byte, error) {
	pkc := pk.Compress()
	return utils.Hex(pkc[:]).MarshalText()
}

// String returns the string representation of the PublicKey
func (pk PublicKey) String() string {
	pkc := pk.Compress()
	return utils.Hex(pkc[:]).String()
}

// UnmarshalText implements the unmarshaler for the PublicKey
func (pk *PublicKey) UnmarshalText(h []byte) error {
	var pkc PublicKeyComp
	if err := utils.HexDecodeInto(pkc[:], h); err != nil {
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
func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

// PublicKeyComp represents a compressed EdDSA Public key; it's a compressed curve
// point.
type PublicKeyComp [32]byte

// MarshalText implements the marshaler for the PublicKeyComp
func (pkComp PublicKeyComp) MarshalText() ([]byte, error) {
	return utils.Hex(pkComp[:]).MarshalText()
}

// String returns the string representation of the PublicKeyComp
func (pkComp PublicKeyComp) String() string { return utils.Hex(pkComp[:]).String() }

// UnmarshalText implements the unmarshaler for the PublicKeyComp
func (pkComp *PublicKeyComp) UnmarshalText(h []byte) error {
	return utils.HexDecodeInto(pkComp[:], h)
}

// Compress returns the PublicKeyCompr for the given PublicKey
func (pk *PublicKey) Compress() PublicKeyComp {
	return PublicKeyComp((*Point)(pk).Compress())
}

// Decompress returns the PublicKey for the given PublicKeyComp
func (pkComp *PublicKeyComp) Decompress() (*PublicKey, error) {
	point, err := NewPoint().Decompress(*pkComp)
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

// MarshalText implements the marshaler for the SignatureComp
func (sComp SignatureComp) MarshalText() ([]byte, error) {
	return utils.Hex(sComp[:]).MarshalText()
}

// String returns the string representation of the SignatureComp
func (sComp SignatureComp) String() string { return utils.Hex(sComp[:]).String() }

// UnmarshalText implements the unmarshaler for the SignatureComp
func (sComp *SignatureComp) UnmarshalText(h []byte) error {
	return utils.HexDecodeInto(sComp[:], h)
}

// Compress an EdDSA signature by concatenating the compression of
// the point R8 and the Little-Endian encoding of S.
func (s *Signature) Compress() SignatureComp {
	R8p := s.R8.Compress()
	Sp := utils.BigIntLEBytes(s.S)
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
	s.S = utils.SetBigIntFromLEBytes(new(big.Int), buf[32:])
	return s, nil
}

// Decompress a compressed signature.  Returns error if the Point decompression
// fails.
func (sComp *SignatureComp) Decompress() (*Signature, error) {
	return new(Signature).Decompress(*sComp)
}

// Scan implements Scanner for database/sql.
func (sComp *SignatureComp) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Signature", src)
	}
	if len(srcB) != 64 {
		return fmt.Errorf("can't scan []byte of len %d into Signature, want %d", len(srcB), 64)
	}
	copy(sComp[:], srcB)
	return nil
}

// Value implements valuer for database/sql.
func (sComp SignatureComp) Value() (driver.Value, error) {
	return sComp[:], nil
}

// Scan implements Scanner for database/sql.
func (s *Signature) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Signature", src)
	}
	if len(srcB) != 64 {
		return fmt.Errorf("can't scan []byte of len %d into Signature, want %d", len(srcB), 64)
	}
	buf := [64]byte{}
	copy(buf[:], srcB)
	_, err := s.Decompress(buf)
	return err
}

// Value implements valuer for database/sql.
func (s Signature) Value() (driver.Value, error) {
	comp := s.Compress()
	return comp[:], nil
}

// SignMimc7 signs a message encoded as a big.Int in Zq using blake-512 hash
// for buffer hashing and mimc7 for big.Int hashing.
func (k *PrivateKey) SignMimc7(msg *big.Int) *Signature {
	h1 := Blake512(k[:])
	msgBuf := utils.BigIntLEBytes(msg)
	msgBuf32 := [32]byte{}
	copy(msgBuf32[:], msgBuf[:])
	rBuf := Blake512(append(h1[32:], msgBuf32[:]...))
	r := utils.SetBigIntFromLEBytes(new(big.Int), rBuf) // r = H(H_{32..63}(k), msg)
	r.Mod(r, SubOrder)
	R8 := NewPoint().Mul(r, B8) // R8 = r * 8 * B
	A := k.Public().Point()
	hmInput := []*big.Int{R8.X, R8.Y, A.X, A.Y, msg}
	hm, err := mimc7.Hash(hmInput, nil) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		panic(err)
	}
	S := new(big.Int).Lsh(k.Scalar().BigInt(), 3)
	S = S.Mul(hm, S)
	S.Add(r, S)
	S.Mod(S, SubOrder) // S = r + hm * 8 * s

	return &Signature{R8: R8, S: S}
}

// VerifyMimc7 verifies the signature of a message encoded as a big.Int in Zq
// using blake-512 hash for buffer hashing and mimc7 for big.Int hashing.
func (pk *PublicKey) VerifyMimc7(msg *big.Int, sig *Signature) bool {
	hmInput := []*big.Int{sig.R8.X, sig.R8.Y, pk.X, pk.Y, msg}
	hm, err := mimc7.Hash(hmInput, nil) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		return false
	}

	left := NewPoint().Mul(sig.S, B8) // left = s * 8 * B
	r1 := big.NewInt(8)
	r1.Mul(r1, hm)
	right := NewPoint().Mul(r1, pk.Point())
	rightProj := right.Projective()
	rightProj.Add(sig.R8.Projective(), rightProj) // right = 8 * R + 8 * hm * A
	right = rightProj.Affine()
	return (left.X.Cmp(right.X) == 0) && (left.Y.Cmp(right.Y) == 0)
}

// SignPoseidon signs a message encoded as a big.Int in Zq using blake-512 hash
// for buffer hashing and Poseidon for big.Int hashing.
func (k *PrivateKey) SignPoseidon(msg *big.Int) *Signature {
	h1 := Blake512(k[:])
	msgBuf := utils.BigIntLEBytes(msg)
	msgBuf32 := [32]byte{}
	copy(msgBuf32[:], msgBuf[:])
	rBuf := Blake512(append(h1[32:], msgBuf32[:]...))
	r := utils.SetBigIntFromLEBytes(new(big.Int), rBuf) // r = H(H_{32..63}(k), msg)
	r.Mod(r, SubOrder)
	R8 := NewPoint().Mul(r, B8) // R8 = r * 8 * B
	A := k.Public().Point()

	hmInput := []*big.Int{R8.X, R8.Y, A.X, A.Y, msg}
	hm, err := poseidon.Hash(hmInput) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		panic(err)
	}

	S := new(big.Int).Lsh(k.Scalar().BigInt(), 3)
	S = S.Mul(hm, S)
	S.Add(r, S)
	S.Mod(S, SubOrder) // S = r + hm * 8 * s

	return &Signature{R8: R8, S: S}
}

// VerifyPoseidon verifies the signature of a message encoded as a big.Int in Zq
// using blake-512 hash for buffer hashing and Poseidon for big.Int hashing.
func (pk *PublicKey) VerifyPoseidon(msg *big.Int, sig *Signature) bool {
	hmInput := []*big.Int{sig.R8.X, sig.R8.Y, pk.X, pk.Y, msg}
	hm, err := poseidon.Hash(hmInput) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		return false
	}

	left := NewPoint().Mul(sig.S, B8) // left = s * 8 * B
	r1 := big.NewInt(8)
	r1.Mul(r1, hm)
	right := NewPoint().Mul(r1, pk.Point())
	rightProj := right.Projective()
	rightProj.Add(sig.R8.Projective(), rightProj) // right = 8 * R + 8 * hm * A
	right = rightProj.Affine()
	return (left.X.Cmp(right.X) == 0) && (left.Y.Cmp(right.Y) == 0)
}

// Scan implements Scanner for database/sql.
func (pk *PublicKey) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into PublicKey", src)
	}
	if len(srcB) != 32 {
		return fmt.Errorf("can't scan []byte of len %d into PublicKey, want %d", len(srcB), 32)
	}
	var comp PublicKeyComp
	copy(comp[:], srcB)
	decomp, err := comp.Decompress()
	if err != nil {
		return err
	}
	*pk = *decomp
	return nil
}

// Value implements valuer for database/sql.
func (pk PublicKey) Value() (driver.Value, error) {
	comp := pk.Compress()
	return comp[:], nil
}

// Scan implements Scanner for database/sql.
func (pkComp *PublicKeyComp) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into PublicKeyComp", src)
	}
	if len(srcB) != 32 {
		return fmt.Errorf("can't scan []byte of len %d into PublicKeyComp, want %d", len(srcB), 32)
	}
	copy(pkComp[:], srcB)
	return nil
}

// Value implements valuer for database/sql.
func (pkComp PublicKeyComp) Value() (driver.Value, error) {
	return pkComp[:], nil
}
