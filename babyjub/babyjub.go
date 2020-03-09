package babyjub

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/ff"
	"github.com/iden3/go-iden3-crypto/utils"
)

// A is one of the babyjub constants.
var A *ff.Element

// D is one of the babyjub constants.
var D *ff.Element

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
	A = ff.NewElement().SetString("168700")
	D = ff.NewElement().SetString("168696")

	Order = utils.NewIntFromString(
		"21888242871839275222246405745257275088614511777268538073601725287587578984328")
	SubOrder = new(big.Int).Rsh(Order, 3)

	B8 = NewPoint()
	B8.X = ff.NewElement().SetString(
		"5299619240641551281634865583518297030282874472190772894086521144482721001553")
	B8.Y = ff.NewElement().SetString(
		"16950150798460657717958625567821834550301663161624707787222815936182638968203")
}

// PointBI represents a point of the babyjub curve.
type PointBI struct {
	X *big.Int
	Y *big.Int
}

type Point struct {
	X *ff.Element
	Y *ff.Element
}

func PointBIToPoint(p *PointBI) *Point {
	return &Point{
		X: ff.NewElement().SetBigInt(p.X),
		Y: ff.NewElement().SetBigInt(p.Y),
	}
}

func PointToPointBI(p *Point) *PointBI {
	return &PointBI{
		X: p.X.BigInt(),
		Y: p.Y.BigInt(),
	}
}

// NewPoint creates a new PointBI.
func NewPointBI() *PointBI {
	return &PointBI{X: big.NewInt(0), Y: big.NewInt(1)}
}

func NewPoint() *Point {
	return &Point{X: ff.NewElement().SetZero(), Y: ff.NewElement().SetOne()}
}

// Set copies a Point c into the Point p
func (p *Point) Set(c *Point) *Point {
	p.X.Set(c.X)
	p.Y.Set(c.Y)
	return p
}

func (p *Point) Equal(q *Point) bool {
	// return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
	return p.X.Equal(q.X) && p.Y.Equal(q.Y)
}

// Add adds Point a and b into res
func (res *Point) Add(a *Point, b *Point) *Point {
	// x = (a.x * b.y + b.x * a.y) * (1 + D * a.x * b.x * a.y * b.y)^-1 mod q
	x1a := ff.NewElement().Mul(a.X, b.Y)
	x1b := ff.NewElement().Mul(b.X, a.Y)
	x1a.Add(x1a, x1b) // x1a = a.x * b.y + b.x * a.y

	x2 := ff.NewElement().Set(D)
	x2.Mul(x2, a.X)
	x2.Mul(x2, b.X)
	x2.Mul(x2, a.Y)
	x2.Mul(x2, b.Y)
	x2.Add(ff.NewElement().SetOne(), x2)
	x2.Inverse(x2) // x2 = (1 + D * a.x * b.x * a.y * b.y)^-1

	// y = (a.y * b.y - A * a.x * b.x) * (1 - D * a.x * b.x * a.y * b.y)^-1 mod q
	y1a := ff.NewElement().Mul(a.Y, b.Y)
	y1b := ff.NewElement().Set(A)
	y1b.Mul(y1b, a.X)
	y1b.Mul(y1b, b.X)

	y1a.Sub(y1a, y1b) // y1a = a.y * b.y - A * a.x * b.x

	y2 := ff.NewElement().Set(D)
	y2.Mul(y2, a.X)
	y2.Mul(y2, b.X)
	y2.Mul(y2, a.Y)
	y2.Mul(y2, b.Y)
	y2.Sub(ff.NewElement().SetOne(), y2)
	y2.Inverse(y2) // y2 = (1 - D * a.x * b.x * a.y * b.y)^-1

	res.X = x1a.Mul(x1a, x2)

	res.Y = y1a.Mul(y1a, y2)

	return res
}

// Mul multiplies the Point p by the scalar s and stores the result in res,
// which is also returned.
func (res *Point) Mul(s *big.Int, p *Point) *Point {
	res.X = ff.NewElement().SetZero()
	res.Y = ff.NewElement().SetOne()
	exp := NewPoint().Set(p)

	for i := 0; i < s.BitLen(); i++ {
		if s.Bit(i) == 1 {
			res.Add(res, exp)
		}
		exp.Add(exp, exp)
	}

	return res
}

// InCurve returns true when the Point p is in the babyjub curve.
func (p *Point) InCurve() bool {
	x2 := ff.NewElement().Set(p.X)
	x2.Mul(x2, x2)

	y2 := ff.NewElement().Set(p.Y)
	y2.Mul(y2, y2)

	a := ff.NewElement().Mul(A, x2)
	a.Add(a, y2)

	b := ff.NewElement().Set(D)
	b.Mul(b, x2)
	b.Mul(b, y2)
	b.Add(ff.NewElement().SetOne(), b)

	return a.Equal(b)
}

// InSubGroup returns true when the Point p is in the subgroup of the babyjub
// curve.
func (p *Point) InSubGroup() bool {
	if !p.InCurve() {
		return false
	}
	res := NewPoint().Mul(SubOrder, p)
	return res.X.Equal(ff.NewElement().SetZero()) && res.Y.Equal(ff.NewElement().SetOne())
}

// PointCoordSign returns the sign of the curve point coordinate.  It returns
// false if the sign is positive and false if the sign is negative.
func PointCoordSign(c *big.Int) bool {
	if c.Cmp(new(big.Int).Rsh(constants.Q, 1)) == 1 {
		return true
	}
	return false
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
	pBI := PointToPointBI(p)
	sign := PointCoordSign(pBI.X)
	return PackPoint(pBI.Y, sign)
}

// Decompress a compressed Point into p, and also returns the decompressed
// Point.  Returns error if the compressed Point is invalid.
func (p *Point) Decompress(leBuf [32]byte) (*Point, error) {
	sign := false
	if (leBuf[31] & 0x80) != 0x00 {
		sign = true
		leBuf[31] = leBuf[31] & 0x7F
	}
	y := big.NewInt(0)
	utils.SetBigIntFromLEBytes(y, leBuf[:])
	if y.Cmp(constants.Q) >= 0 {
		return nil, fmt.Errorf("p.y >= Q")
	}
	p.Y = ff.NewElement().SetBigInt(y)

	y2 := ff.NewElement().Mul(p.Y, p.Y)
	xa := ff.NewElement().SetOne()
	xa.Sub(xa, y2) // xa == 1 - y^2

	xb := ff.NewElement().Mul(D, y2)
	xb.Sub(A, xb) // xb = A - d * y^2

	if xb.Equal(ff.NewElement().SetZero()) {
		return nil, fmt.Errorf("division by 0")
	}
	xb.Inverse(xb)
	p.X.Mul(xa, xb) // xa / xb

	q := PointToPointBI(p)
	noSqrt := q.X.ModSqrt(q.X, constants.Q)
	if noSqrt == nil {
		return nil, fmt.Errorf("x is not a square mod q")
	}
	if (sign && !PointCoordSign(q.X)) || (!sign && PointCoordSign(q.X)) {
		q.X.Mul(q.X, constants.MinusOne)
	}
	q.X.Mod(q.X, constants.Q)

	p = PointBIToPoint(q)

	return p, nil
}
