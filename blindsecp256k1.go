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
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// G represents the base point of secp256k1
	G *Point = &Point{
		X: btcec.S256().Gx,
		Y: btcec.S256().Gy,
	}

	// N represents the order of G of secp256k1
	N *big.Int = btcec.S256().N

	// B (from y^2 = x^3 + B)
	B *big.Int = btcec.S256().B

	// Q = (P+1)/4
	Q = new(big.Int).Div(new(big.Int).Add(btcec.S256().P,
		big.NewInt(1)), big.NewInt(4))
)

// Point represents a point on the secp256k1 curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// Add performs the Point addition
func (p *Point) Add(q *Point) *Point {
	x, y := btcec.S256().Add(p.X, p.Y, q.X, q.Y)
	return &Point{
		X: x,
		Y: y,
	}
}

// Mul performs the Point scalar multiplication
func (p *Point) Mul(scalar *big.Int) *Point {
	x, y := btcec.S256().ScalarMult(p.X, p.Y, scalar.Bytes())
	return &Point{
		X: x,
		Y: y,
	}
}

func (p *Point) Compress() [33]byte {
	xBytes := p.X.Bytes()
	sign := byte(0)
	if isOdd(p.Y) {
		sign = byte(1)
	}
	var b [33]byte
	copy(b[32-len(xBytes):32], xBytes)
	b[32] = sign
	return b
}

func isOdd(b *big.Int) bool {
	return b.Bit(0) != 0
}

func squareMul(r, x *big.Int, bit bool) *big.Int {
	// r = new(big.Int).Mul(r, r) // r^2
	r = new(big.Int).Exp(r, big.NewInt(2), N)
	if bit {
		r = new(big.Int).Mul(r, x)
	}
	return new(big.Int).Mod(r, N)
}

// https://en.wikipedia.org/wiki/Exponentiation_by_squaring
func sqrtQ(x *big.Int) *big.Int {
	// xBytes := x.Bytes()
	qBytes := Q.Bytes()
	r := big.NewInt(1)
	// fmt.Println(hex.EncodeToString(qBytes))
	for _, b := range qBytes {
		// fmt.Printf("%d, %x %d\n", i, b, r)
		// fmt.Printf("%x %s\n", b, r.String())
		switch b {
		// Most common case, where all 8 bits are set.
		case 0xff:
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			// fmt.Printf("%x %s\n", b, r.String())

		// First byte of Q (0x3f), where all but the top two bits are
		// set. Note that this case only applies six operations, since
		// the highest bit of Q resides in bit six of the first byte. We
		// ignore the first two bits, since squaring for these bits will
		// result in an invalid result. We forgo squaring f before the
		// first multiply, since 1^2 = 1.
		case 0x3f:
			r = new(big.Int).Mul(r, x)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)

		// Byte 28 of Q (0xbf), where only bit 7 is unset.
		case 0xbf:
			r = squareMul(r, x, true)
			r = squareMul(r, x, false)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)

		// Byte 31 of Q (0x0c), where only bits 3 and 4 are set.
		default:
			r = squareMul(r, x, false)
			r = squareMul(r, x, false)
			r = squareMul(r, x, false)
			r = squareMul(r, x, false)
			r = squareMul(r, x, true)
			r = squareMul(r, x, true)
			r = squareMul(r, x, false)
			r = squareMul(r, x, false)
		}
	}
	return r
}

// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
// func (p *Point) Decompress(b [33]byte) error {
func Decompress(b [33]byte) (*Point, error) {
	fmt.Println(b)
	x := new(big.Int).SetBytes(b[:32])
	fmt.Println(x)
	var sign bool
	if b[32] == byte(1) {
		sign = true
	}

	// y2 = x3+ ax2 + b (where A==0, B==7)

	// compute x^3 + B mod p
	x3 := new(big.Int).Mul(x, x)
	x3 = new(big.Int).Mul(x3, x)
	// x3 := new(big.Int).Exp(x, big.NewInt(3), N)
	x3 = new(big.Int).Add(x3, B)
	x3 = new(big.Int).Mod(x3, N)

	// sqrt mod p of x^3 + B
	fmt.Println("x3", x3)
	y := new(big.Int).ModSqrt(x3, N)
	// y := sqrtQ(x3)
	if y == nil {
		return nil, fmt.Errorf("not sqrt mod of x^3")
	}
	fmt.Println("y", y)
	fmt.Println("y", new(big.Int).Sub(N, y))
	fmt.Println("y", new(big.Int).Mod(new(big.Int).Neg(y), N))
	if sign != isOdd(y) {
		y = new(big.Int).Sub(N, y)
		// TODO check if needed Mod
	}

	// check that y is a square root of x^3 + B
	y2 := new(big.Int).Mul(y, y)
	y2 = new(big.Int).Mod(y2, N)
	if !bytes.Equal(y2.Bytes(), x3.Bytes()) {
		return nil, fmt.Errorf("invalid square root")
	}

	if sign != isOdd(y) {
		return nil, fmt.Errorf("sign does not match oddness")
	}

	p := &Point{X: x, Y: y}
	// p = &Point{}
	// p.X = x
	// p.Y = y
	// fmt.Println("I", p.X, p.Y)
	return p, nil
}

// WIP
func newRand() *big.Int {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	bi := new(big.Int).SetBytes(b[:])
	return new(big.Int).Mod(bi, N)
}

// PrivateKey represents the signer's private key
type PrivateKey big.Int

// PublicKey represents the signer's public key
type PublicKey Point

// NewPrivateKey returns a new random private key
func NewPrivateKey() *PrivateKey {
	k := newRand()
	sk := PrivateKey(*k)
	return &sk
}

// BigInt returns a *big.Int representation of the PrivateKey
func (sk *PrivateKey) BigInt() *big.Int {
	return (*big.Int)(sk)
}

// Public returns the PublicKey from the PrivateKey
func (sk *PrivateKey) Public() *PublicKey {
	Q := G.Mul(sk.BigInt())
	pk := PublicKey(*Q)
	return &pk
}

// Point returns a *Point representation of the PublicKey
func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

// NewRequestParameters returns a new random k (secret) & R (public) parameters
func NewRequestParameters() (*big.Int, *Point) {
	k := newRand()
	return k, G.Mul(k) // R = kG
}

// BlindSign performs the blind signature on the given mBlinded using the
// PrivateKey and the secret k values
func (sk *PrivateKey) BlindSign(mBlinded *big.Int, k *big.Int) *big.Int {
	// TODO add pending checks
	// s' = dm' + k
	sBlind := new(big.Int).Add(
		new(big.Int).Mul(sk.BigInt(), mBlinded),
		k)
	return sBlind
}

// UserSecretData contains the secret values from the User (a, b, c) and the
// public F
type UserSecretData struct {
	A *big.Int
	B *big.Int

	F *Point // public (in the paper is R)
}

// Blind performs the blinding operation on m using signerR parameter
func Blind(m *big.Int, signerR *Point) (*big.Int, *UserSecretData) {
	u := &UserSecretData{}
	u.A = newRand()
	u.B = newRand()

	// (R) F = aR' + bG
	aR := signerR.Mul(u.A)
	bG := G.Mul(u.B)
	u.F = aR.Add(bG)

	// TODO check that F != O (point at infinity)

	rx := new(big.Int).Mod(u.F.X, N)

	// m' = a^-1 rx h(m)
	ainv := new(big.Int).ModInverse(u.A, N)
	ainvrx := new(big.Int).Mul(ainv, rx)
	hBytes := crypto.Keccak256(m.Bytes())
	h := new(big.Int).SetBytes(hBytes)
	mBlinded := new(big.Int).Mul(ainvrx, h)

	return mBlinded, u
}

// Signature contains the signature values S & F
type Signature struct {
	S *big.Int
	F *Point
}

// Unblind performs the unblinding operation of the blinded signature for the
// given message m and the UserSecretData
func Unblind(sBlind, m *big.Int, u *UserSecretData) *Signature {
	// s = a s' + b
	as := new(big.Int).Mul(u.A, sBlind)
	s := new(big.Int).Add(as, u.B)

	return &Signature{
		S: s,
		F: u.F,
	}
}

// Verify checks the signature of the message m for the given PublicKey
func Verify(m *big.Int, s *Signature, q *PublicKey) bool {
	// TODO add pending checks

	sG := G.Mul(s.S) // sG

	hBytes := crypto.Keccak256(m.Bytes())
	h := new(big.Int).SetBytes(hBytes)

	rx := new(big.Int).Mod(s.F.X, N)
	rxh := new(big.Int).Mul(rx, h)
	// rxhG := G.Mul(rxh) // originally the paper uses G
	rxhG := q.Point().Mul(rxh)

	right := s.F.Add(rxhG)

	// check sG == R + rx h(m) G (where R in this code is F)
	if bytes.Equal(sG.X.Bytes(), right.X.Bytes()) &&
		bytes.Equal(sG.Y.Bytes(), right.Y.Bytes()) {
		return true
	}
	return false
}
