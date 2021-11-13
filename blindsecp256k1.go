// Package blindsecp256k1 implements the Blind signature scheme explained at
// "New Blind Signature Schemes Based on the (Elliptic Curve) Discrete
// Logarithm Problem", by Hamid Mala & Nafiseh Nezhadansari
// https://sci-hub.do/10.1109/ICCKE.2013.6682844
//
// LICENSE can be found at https://github.com/arnaucube/go-blindsecp256k1/blob/master/LICENSE
//
package blindsecp256k1

// WARNING: WIP code

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// TMP
// const (
//         // MinBigIntBytesLen defines the minimum bytes length of the minimum
//         // accepted value for the checked *big.Int
//         MinBigIntBytesLen = 20 * 8
// )

var (
	zero *big.Int = big.NewInt(0)
)

// Curve is a curve wrapper that works with Point structs
type Curve struct {
	c elliptic.Curve
}

// Point represents a point on the secp256k1 curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// Add performs the Point addition
func (c Curve) Add(p, q *Point) *Point {
	x, y := c.c.Add(p.X, p.Y, q.X, q.Y)
	return &Point{
		X: x,
		Y: y,
	}
}

// Mul performs the Point scalar multiplication
func (c Curve) Mul(p *Point, scalar *big.Int) *Point {
	x, y := c.c.ScalarMult(p.X, p.Y, scalar.Bytes())
	return &Point{
		X: x,
		Y: y,
	}
}

func (c Curve) isValid(p *Point) error {
	if !c.c.IsOnCurve(p.X, p.Y) {
		return fmt.Errorf("Point is not on curve %s", c.c.Params().Name)
	}

	if bytes.Equal(p.X.Bytes(), zero.Bytes()) &&
		bytes.Equal(p.Y.Bytes(), zero.Bytes()) {
		return fmt.Errorf("Point (%s, %s) can not be (0, 0)",
			p.X.String(), p.Y.String())
	}
	return nil
}

// Compress packs a Point to a byte array of 33 bytes, encoded in little-endian.
func (p *Point) Compress() [33]byte {
	xBytes := p.X.Bytes()
	odd := byte(0)
	if isOdd(p.Y) {
		odd = byte(1)
	}
	var b [33]byte
	copy(b[32-len(xBytes):32], xBytes)
	b[32] = odd
	return b
}

func isOdd(b *big.Int) bool {
	return b.Bit(0) != 0
}

// DecompressPoint unpacks a Point from the given byte array of 33 bytes
// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
func DecompressPoint(curv elliptic.Curve, b [33]byte) (*Point, error) {
	x := new(big.Int).SetBytes(b[:32])
	var odd bool
	if b[32] == byte(1) {
		odd = true
	}

	// secp256k1: y2 = x3+ ax2 + b (where A==0, B==7)
	params := curv.Params()
	B := params.B
	P := params.P

	// compute x^3 + B mod p
	x3 := new(big.Int).Mul(x, x)
	x3 = new(big.Int).Mul(x3, x)
	// x3 := new(big.Int).Exp(x, big.NewInt(3), nil)
	x3 = new(big.Int).Add(x3, B)
	x3 = new(big.Int).Mod(x3, P)

	// sqrt mod p of x^3 + B
	y := new(big.Int).ModSqrt(x3, P)
	if y == nil {
		return nil, fmt.Errorf("not sqrt mod of x^3")
	}
	if odd != isOdd(y) {
		y = new(big.Int).Sub(P, y)
		// TODO if needed Mod
	}

	// check that y is a square root of x^3 + B
	y2 := new(big.Int).Mul(y, y)
	y2 = new(big.Int).Mod(y2, P)
	if !bytes.Equal(y2.Bytes(), x3.Bytes()) {
		return nil, fmt.Errorf("invalid square root")
	}

	if odd != isOdd(y) {
		return nil, fmt.Errorf("odd does not match oddness")
	}

	p := &Point{X: x, Y: y}
	return p, nil
}

// WIP
func newRand(curv elliptic.Curve) *big.Int {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	bi := new(big.Int).SetBytes(b[:])
	return new(big.Int).Mod(bi, curv.Params().N)
}

// PrivateKey represents the signer's private key
type PrivateKey big.Int

// PublicKey represents the signer's public key
type PublicKey Point

// NewPrivateKey returns a new random private key
func NewPrivateKey(curv elliptic.Curve) *PrivateKey {
	k := newRand(curv)
	sk := PrivateKey(*k)
	return &sk
}

// BigInt returns a *big.Int representation of the PrivateKey
func (sk *PrivateKey) BigInt() *big.Int {
	return (*big.Int)(sk)
}

// Public returns the PublicKey from the PrivateKey
func (sk *PrivateKey) Public(curv elliptic.Curve) *PublicKey {
	// TODO change impl to use directly X, Y instead
	// of Point wrapper. In order to have the impl more close to go interface
	c := Curve{curv}
	G := &Point{
		X: c.c.Params().Gx,
		Y: c.c.Params().Gy,
	}
	q := c.Mul(G, sk.BigInt())
	pk := PublicKey{X: q.X, Y: q.Y}
	return &pk
}

// Point returns a *Point representation of the PublicKey
func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

// NewRequestParameters returns a new random k (secret) & R (public) parameters
func NewRequestParameters(curv elliptic.Curve) (*big.Int, *Point) {
	k := newRand(curv)
	G := &Point{
		X: curv.Params().Gx,
		Y: curv.Params().Gy,
	}
	// R = kG
	r := Curve{curv}.Mul(G, k)
	return k, r
}

// BlindSign performs the blind signature on the given mBlinded using the
// PrivateKey and the secret k values
func (sk *PrivateKey) BlindSign(curv elliptic.Curve, mBlinded *big.Int, k *big.Int) (*big.Int, error) {
	c := Curve{curv}
	n := c.c.Params().N
	// TODO add pending checks
	if mBlinded.Cmp(n) != -1 {
		return nil, fmt.Errorf("mBlinded not inside the finite field")
	}
	if bytes.Equal(mBlinded.Bytes(), big.NewInt(0).Bytes()) {
		return nil, fmt.Errorf("mBlinded can not be 0")
	}
	// TMP
	// if mBlinded.BitLen() < MinBigIntBytesLen {
	//         return nil, fmt.Errorf("mBlinded too small")
	// }

	// s' = dm' + k
	sBlind := new(big.Int).Add(
		new(big.Int).Mul(sk.BigInt(), mBlinded),
		k)
	sBlind = new(big.Int).Mod(sBlind, n)
	return sBlind, nil
}

// UserSecretData contains the secret values from the User (a, b) and the
// public F
type UserSecretData struct {
	A *big.Int
	B *big.Int

	F *Point // public (in the paper is named R)
}

// Blind performs the blinding operation on m using signerR parameter
func Blind(curv elliptic.Curve, m *big.Int, signerR *Point) (*big.Int, *UserSecretData, error) {
	c := Curve{curv}
	if err := c.isValid(signerR); err != nil {
		return nil, nil, fmt.Errorf("signerR %s", err)
	}

	// TODO check if curv==signerR.curv
	// TODO (once the Point abstraction is removed) check that signerR is
	// in the curve
	G := &Point{
		X: curv.Params().Gx,
		Y: curv.Params().Gy,
	}

	u := &UserSecretData{}
	u.A = newRand(curv)
	u.B = newRand(curv)

	// (R) F = aR' + bG
	aR := c.Mul(signerR, u.A)
	bG := c.Mul(G, u.B)
	u.F = c.Add(aR, bG)

	// TODO check that F != O (point at infinity)
	if err := c.isValid(u.F); err != nil {
		return nil, nil, fmt.Errorf("u.F %s", err)
	}

	rx := new(big.Int).Mod(u.F.X, curv.Params().N)

	// m' = a^-1 rx h(m)
	ainv := new(big.Int).ModInverse(u.A, curv.Params().N)
	ainvrx := new(big.Int).Mul(ainv, rx)
	hBytes := crypto.Keccak256(m.Bytes())
	h := new(big.Int).SetBytes(hBytes)
	mBlinded := new(big.Int).Mul(ainvrx, h)
	mBlinded = new(big.Int).Mod(mBlinded, curv.Params().N)

	return mBlinded, u, nil
}

// Signature contains the signature values S & F
type Signature struct {
	S *big.Int
	F *Point
}

// Compress packs a Signature to a byte array of 65 bytes, encoded in
// little-endian.
func (s *Signature) Compress() [65]byte {
	var b [65]byte
	sBytes := s.S.Bytes()
	fBytes := s.F.Compress()
	copy(b[:32], swapEndianness(sBytes))
	copy(b[32:], fBytes[:])
	return b
}

// DecompressSignature unpacks a Signature from the given byte array of 65 bytes
func DecompressSignature(curve elliptic.Curve, b [65]byte) (*Signature, error) {
	s := new(big.Int).SetBytes(swapEndianness(b[:32]))
	var fBytes [33]byte
	copy(fBytes[:], b[32:])
	f, err := DecompressPoint(curve, fBytes)
	if err != nil {
		return nil, err
	}
	sig := &Signature{S: s, F: f}
	return sig, nil
}

// Unblind performs the unblinding operation of the blinded signature for the
// given the UserSecretData
func Unblind(curv elliptic.Curve, sBlind *big.Int, u *UserSecretData) *Signature {
	// s = a s' + b
	as := new(big.Int).Mul(u.A, sBlind)
	s := new(big.Int).Add(as, u.B)
	s = new(big.Int).Mod(s, curv.Params().N)

	return &Signature{
		S: s,
		F: u.F,
	}
}

// Verify checks the signature of the message m for the given PublicKey
func Verify(curv elliptic.Curve, m *big.Int, s *Signature, q *PublicKey) bool {
	// TODO add pending checks
	c := Curve{curv}
	if err := c.isValid(s.F); err != nil {
		return false
	}
	if err := c.isValid(q.Point()); err != nil {
		return false
	}

	G := &Point{
		X: curv.Params().Gx,
		Y: curv.Params().Gy,
	}
	sG := c.Mul(G, s.S) // sG

	hBytes := crypto.Keccak256(m.Bytes())
	h := new(big.Int).SetBytes(hBytes)

	rx := new(big.Int).Mod(s.F.X, curv.Params().N)
	rxh := new(big.Int).Mul(rx, h)
	// rxhG := G.Mul(rxh) // originally the paper uses G
	rxhG := c.Mul(q.Point(), rxh)

	right := c.Add(s.F, rxhG)

	// check sG == R + rx h(m) Q (where R in this code is F)
	if bytes.Equal(sG.X.Bytes(), right.X.Bytes()) &&
		bytes.Equal(sG.Y.Bytes(), right.Y.Bytes()) {
		return true
	}
	return false
}
