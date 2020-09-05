package babyjub

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/utils"
)

// A is one of the babyjub constants.
var A *big.Int

// D is one of the babyjub constants.
var D *big.Int

// Order of the babyjub curve.
var Order *big.Int

// SubOrder is the order of the subgroup of the babyjub curve that contains the
// points that we use.
var SubOrder *big.Int

// B8 is a base point of the babyjub multiplied by 8 to make it a base point of
// the subgroup in the curve.
var B8 *Point

// init initializes global numbers and the subgroup base.
func init() {
	A = utils.NewIntFromString("168700")
	D = utils.NewIntFromString("168696")

	Order = utils.NewIntFromString(
		"21888242871839275222246405745257275088614511777268538073601725287587578984328")
	SubOrder = new(big.Int).Rsh(Order, 3)

	B8 = NewPoint()
	B8.X = utils.NewIntFromString(
		"5299619240641551281634865583518297030282874472190772894086521144482721001553")
	B8.Y = utils.NewIntFromString(
		"16950150798460657717958625567821834550301663161624707787222815936182638968203")
}

// PointProjective is the Point representation in projective coordinates
type PointProjective struct {
	X *big.Int
	Y *big.Int
	Z *big.Int
}

// NewPointProjective creates a new Point in projective coordinates.
func NewPointProjective() *PointProjective {
	return &PointProjective{X: big.NewInt(0), Y: big.NewInt(1), Z: big.NewInt(1)}
}

// Affine returns the Point from the projective representation
func (p *PointProjective) Affine() *Point {
	if bytes.Equal(p.Z.Bytes(), big.NewInt(0).Bytes()) {
		return &Point{
			X: big.NewInt(0),
			Y: big.NewInt(0),
		}
	}
	zinv := new(big.Int).ModInverse(p.Z, constants.Q)
	x := new(big.Int).Mul(p.X, zinv)
	x.Mod(x, constants.Q)
	y := new(big.Int).Mul(p.Y, zinv)
	y.Mod(y, constants.Q)
	return &Point{
		X: x,
		Y: y,
	}
}

// Add computes the addition of two points in projective coordinates representation
func (res *PointProjective) Add(p *PointProjective, q *PointProjective) *PointProjective {
	// add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#doubling-dbl-2008-bbjlp
	a := new(big.Int).Mul(p.Z, q.Z)
	b := new(big.Int).Set(a)
	b.Exp(b, big.NewInt(2), constants.Q)
	c := new(big.Int).Mul(p.X, q.X)
	c.Mod(c, constants.Q) // apply Mod to reduce number file and speed computation
	d := new(big.Int).Mul(p.Y, q.Y)
	d.Mod(d, constants.Q)
	e := new(big.Int).Mul(D, c)
	e.Mul(e, d)
	e.Mod(e, constants.Q)
	f := new(big.Int).Sub(b, e)
	f.Mod(f, constants.Q)
	g := new(big.Int).Add(b, e)
	g.Mod(g, constants.Q)
	x1y1 := new(big.Int).Add(p.X, p.Y)
	x2y2 := new(big.Int).Add(q.X, q.Y)
	x3 := new(big.Int).Mul(x1y1, x2y2)
	x3.Sub(x3, c)
	x3.Sub(x3, d)
	x3.Mul(x3, a)
	x3.Mul(x3, f)
	x3.Mod(x3, constants.Q)
	ac := new(big.Int).Mul(A, c)
	y3 := new(big.Int).Sub(d, ac)
	y3.Mul(y3, a)
	y3.Mul(y3, g)
	y3.Mod(y3, constants.Q)
	z3 := new(big.Int).Mul(f, g)
	z3.Mod(z3, constants.Q)

	res.X = x3
	res.Y = y3
	res.Z = z3
	return res
}

// Point represents a point of the babyjub curve.
type Point struct {
	X *big.Int
	Y *big.Int
}

// NewPoint creates a new Point.
func NewPoint() *Point {
	return &Point{X: big.NewInt(0), Y: big.NewInt(1)}
}

// Set copies a Point c into the Point p
func (p *Point) Set(c *Point) *Point {
	p.X.Set(c.X)
	p.Y.Set(c.Y)
	return p
}

// Projective returns a PointProjective from the Point
func (p *Point) Projective() *PointProjective {
	return &PointProjective{
		X: p.X,
		Y: p.Y,
		Z: big.NewInt(1),
	}
}

// Mul multiplies the Point p by the scalar s and stores the result in res,
// which is also returned.
func (res *Point) Mul(s *big.Int, p *Point) *Point {
	resProj := &PointProjective{
		X: big.NewInt(0),
		Y: big.NewInt(1),
		Z: big.NewInt(1),
	}
	exp := p.Projective()

	for i := 0; i < s.BitLen(); i++ {
		if s.Bit(i) == 1 {
			resProj.Add(resProj, exp)
		}
		exp = exp.Add(exp, exp)
	}
	res = resProj.Affine()
	return res
}

// InCurve returns true when the Point p is in the babyjub curve.
func (p *Point) InCurve() bool {
	x2 := new(big.Int).Set(p.X)
	x2.Mul(x2, x2)
	x2.Mod(x2, constants.Q)

	y2 := new(big.Int).Set(p.Y)
	y2.Mul(y2, y2)
	y2.Mod(y2, constants.Q)

	a := new(big.Int).Mul(A, x2)
	a.Add(a, y2)
	a.Mod(a, constants.Q)

	b := new(big.Int).Set(D)
	b.Mul(b, x2)
	b.Mul(b, y2)
	b.Add(constants.One, b)
	b.Mod(b, constants.Q)

	return a.Cmp(b) == 0
}

// InSubGroup returns true when the Point p is in the subgroup of the babyjub
// curve.
func (p *Point) InSubGroup() bool {
	if !p.InCurve() {
		return false
	}
	res := NewPoint().Mul(SubOrder, p)
	return (res.X.Cmp(constants.Zero) == 0) && (res.Y.Cmp(constants.One) == 0)
}

// PointCoordSign returns the sign of the curve point coordinate.  It returns
// false if the sign is positive and false if the sign is negative.
func PointCoordSign(c *big.Int) bool {
	return c.Cmp(new(big.Int).Rsh(constants.Q, 1)) == 1
}

func PackPoint(ay *big.Int, sign bool) [32]byte {
	leBuf := utils.BigIntLEBytes(ay)
	if sign {
		leBuf[31] = leBuf[31] | 0x80
	}
	return leBuf
}

// Compress the point into a 32 byte array that contains the y coordinate in
// little endian and the sign of the x coordinate.
func (p *Point) Compress() [32]byte {
	sign := PointCoordSign(p.X)
	return PackPoint(p.Y, sign)
}

// Decompress a compressed Point into p, and also returns the decompressed
// Point.  Returns error if the compressed Point is invalid.
func (p *Point) Decompress(leBuf [32]byte) (*Point, error) {
	sign := false
	if (leBuf[31] & 0x80) != 0x00 {
		sign = true
		leBuf[31] = leBuf[31] & 0x7F
	}
	utils.SetBigIntFromLEBytes(p.Y, leBuf[:])
	return PointFromSignAndY(sign, p.Y)
}

// PointFromSignAndY returns a Point from a Sign and the Y coordinate
func PointFromSignAndY(sign bool, y *big.Int) (*Point, error) {
	var p Point
	p.X = big.NewInt(0)
	p.Y = y
	if p.Y.Cmp(constants.Q) >= 0 {
		return nil, fmt.Errorf("p.y >= Q")
	}

	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, constants.Q)
	xa := big.NewInt(1)
	xa.Sub(xa, y2) // xa == 1 - y^2

	xb := new(big.Int).Mul(D, y2)
	xb.Mod(xb, constants.Q)
	xb.Sub(A, xb) // xb = A - d * y^2

	if xb.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("division by 0")
	}
	xb.ModInverse(xb, constants.Q)
	p.X.Mul(xa, xb) // xa / xb
	p.X.Mod(p.X, constants.Q)
	noSqrt := p.X.ModSqrt(p.X, constants.Q)
	if noSqrt == nil {
		return nil, fmt.Errorf("x is not a square mod q")
	}
	if (sign && !PointCoordSign(p.X)) || (!sign && PointCoordSign(p.X)) {
		p.X.Mul(p.X, constants.MinusOne)
	}
	p.X.Mod(p.X, constants.Q)

	return &p, nil
}
