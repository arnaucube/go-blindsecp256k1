// Package blindsecp256k1 implements the Blind signature scheme explained at
// "New Blind Signature Schemes Based on the (Elliptic Curve) Discrete
// Logarithm Problem", by Hamid Mala & Nafiseh Nezhadansari
// https://sci-hub.st/10.1109/ICCKE.2013.6682844
//
// LICENSE can be found at https://github.com/arnaucube/go-blindsecp256k1/blob/master/LICENSE
//
package blindsecp256k1

// WARNING: WIP code

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	s256 *secp256k1.BitCurve = secp256k1.S256()
	zero *big.Int            = big.NewInt(0)

	// B (from y^2 = x^3 + B)
	B *big.Int = s256.B

	// P represents the secp256k1 finite field
	P *big.Int = s256.P

	// G represents the base point of secp256k1
	G *Point = &Point{
		X: s256.Gx,
		Y: s256.Gy,
	}

	// N represents the order of G of secp256k1
	N *big.Int = s256.N
)

// Point represents a point on the secp256k1 curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// Add performs the Point addition
func (p *Point) Add(q *Point) *Point {
	x, y := s256.Add(p.X, p.Y, q.X, q.Y)
	return &Point{
		X: x,
		Y: y,
	}
}

// Mul performs the Point scalar multiplication
func (p *Point) Mul(scalar *big.Int) *Point {
	x, y := s256.ScalarMult(p.X, p.Y, scalar.Bytes())
	return &Point{
		X: x,
		Y: y,
	}
}

func (p *Point) isValid() error {
	if !s256.IsOnCurve(p.X, p.Y) {
		return fmt.Errorf("Point is not on secp256k1")
	}

	if bytes.Equal(p.X.Bytes(), zero.Bytes()) &&
		bytes.Equal(p.Y.Bytes(), zero.Bytes()) {
		return fmt.Errorf("Point (%s, %s) can not be (0, 0)",
			p.X.String(), p.Y.String())
	}
	return nil
}

// Compress packs a Point to a byte array of 33 bytes, encoded in
// little-endian.
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
func DecompressPoint(b [33]byte) (*Point, error) {
	x := new(big.Int).SetBytes(b[:32])
	var odd bool
	if b[32] == byte(1) {
		odd = true
	}

	// secp256k1: y2 = x3+ ax2 + b (where A==0, B==7)

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
	return p, p.isValid()
}

// WIP
func newRand() (*big.Int, error) {
	pk, err := ecdsa.GenerateKey(s256, rand.Reader)
	if err != nil {
		return nil, err
	}
	return pk.D, nil
}

// PrivateKey represents the signer's private key
type PrivateKey big.Int

// PublicKey represents the signer's public key
type PublicKey Point

// NewPrivateKey returns a new random private key
func NewPrivateKey() (*PrivateKey, error) {
	k, err := newRand()
	if err != nil {
		return nil, err
	}
	if err := checkBigIntSize(k); err != nil {
		return nil, fmt.Errorf("k error: %s", err)
	}
	sk := PrivateKey(*k)
	return &sk, nil
}

// BigInt returns a *big.Int representation of the PrivateKey
func (sk *PrivateKey) BigInt() *big.Int {
	return (*big.Int)(sk)
}

// Public returns the PublicKey from the PrivateKey
func (sk *PrivateKey) Public() *PublicKey {
	q := G.Mul(sk.BigInt())
	pk := PublicKey(*q)
	return &pk
}

// Point returns a *Point representation of the PublicKey
func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

// NewRequestParameters returns a new random k (secret) & R (public) parameters
func NewRequestParameters() (*big.Int, *Point, error) {
	k, err := newRand()
	if err != nil {
		return nil, nil, err
	}
	// k, R = kG
	return k, G.Mul(k), nil
}

func checkBigIntSize(b *big.Int) error {
	// check b.Bytes()==32, as go returns big-endian representation of the
	// bigint, so if length is not 32 we have a smaller value than expected
	// if len(b.Bytes()) != 32 { //nolint:gomnd
	//         return fmt.Errorf("invalid length, need 32 bytes")
	// }
	return nil
}

// BlindSign performs the blind signature on the given mBlinded using the
// PrivateKey and the secret k values.
func (sk *PrivateKey) BlindSign(mBlinded *big.Int, k *big.Int) (*big.Int, error) {
	// TODO add pending checks
	if mBlinded.Cmp(N) != -1 {
		return nil, fmt.Errorf("mBlinded not inside the finite field")
	}
	if bytes.Equal(mBlinded.Bytes(), big.NewInt(0).Bytes()) {
		return nil, fmt.Errorf("mBlinded can not be 0")
	}
	if err := checkBigIntSize(mBlinded); err != nil {
		return nil, fmt.Errorf("mBlinded error: %s", err)
	}
	if err := checkBigIntSize(k); err != nil {
		return nil, fmt.Errorf("k error: %s", err)
	}

	// s' = dm' + k
	sBlind := new(big.Int).Add(
		new(big.Int).Mul(sk.BigInt(), mBlinded),
		k)
	sBlind = new(big.Int).Mod(sBlind, N)
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
func Blind(m *big.Int, signerR *Point) (*big.Int, *UserSecretData, error) {
	if err := signerR.isValid(); err != nil {
		return nil, nil, fmt.Errorf("signerR %s", err)
	}

	var err error
	u := &UserSecretData{}
	u.A, err = newRand()
	if err != nil {
		return nil, nil, err
	}
	u.B, err = newRand()
	if err != nil {
		return nil, nil, err
	}

	// (R) F = aR' + bG
	aR := signerR.Mul(u.A)
	bG := G.Mul(u.B)
	u.F = aR.Add(bG)

	if err := u.F.isValid(); err != nil {
		return nil, nil, fmt.Errorf("u.F %s", err)
	}

	rx := new(big.Int).Mod(u.F.X, N)

	// m' = a^-1 rx h(m)
	ainv := new(big.Int).ModInverse(u.A, N)
	ainvrx := new(big.Int).Mul(ainv, rx)
	hBytes := crypto.Keccak256(m.Bytes())
	h := new(big.Int).SetBytes(hBytes)
	mBlinded := new(big.Int).Mul(ainvrx, h)
	mBlinded = new(big.Int).Mod(mBlinded, N)

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
func DecompressSignature(b [65]byte) (*Signature, error) {
	s := new(big.Int).SetBytes(swapEndianness(b[:32]))
	var fBytes [33]byte
	copy(fBytes[:], b[32:])
	f, err := DecompressPoint(fBytes)
	if err != nil {
		return nil, err
	}
	sig := &Signature{S: s, F: f}
	return sig, nil
}

// Unblind performs the unblinding operation of the blinded signature for the
// given the UserSecretData
func Unblind(sBlind *big.Int, u *UserSecretData) *Signature {
	// s = a s' + b
	as := new(big.Int).Mul(u.A, sBlind)
	s := new(big.Int).Add(as, u.B)
	s = new(big.Int).Mod(s, N)

	return &Signature{
		S: s,
		F: u.F,
	}
}

// Verify checks the signature of the message m for the given PublicKey
func Verify(m *big.Int, s *Signature, q *PublicKey) bool {
	// TODO add pending checks
	if err := s.F.isValid(); err != nil {
		return false
	}
	if err := q.Point().isValid(); err != nil {
		return false
	}

	sG := G.Mul(s.S) // sG

	hBytes := crypto.Keccak256(m.Bytes())
	h := new(big.Int).SetBytes(hBytes)

	rx := new(big.Int).Mod(s.F.X, N)
	rxh := new(big.Int).Mul(rx, h)
	// do mod, as go-ethereum/crypto/secp256k1 can not handle scalars > 256 bits
	rxhMod := new(big.Int).Mod(rxh, N)
	// rxhG := G.Mul(rxh) // originally the paper uses G
	rxhG := q.Point().Mul(rxhMod)

	right := s.F.Add(rxhG)

	// check sG == R + rx h(m) Q (where R in this code is F)
	if bytes.Equal(sG.X.Bytes(), right.X.Bytes()) &&
		bytes.Equal(sG.Y.Bytes(), right.Y.Bytes()) {
		return true
	}
	return false
}
