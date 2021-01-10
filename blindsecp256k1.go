// Package blindsecp256k1 implements the Blind signature scheme explained at
// http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf
//
// LICENSE can be found at https://github.com/arnaucube/go-blindsecp256k1/blob/master/LICENSE
//
package blindsecp256k1

// WARNING: WIP code

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var (
	// G represents the base point of secp256k1
	G *Point = &Point{
		X: btcec.S256().Gx,
		Y: btcec.S256().Gy,
	}

	// N represents the order of G of secp256k1
	N *big.Int = btcec.S256().N
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

// SignerPrivateData contains the secret values from the Signer
type SignerPrivateData struct {
	D *PrivateKey
	K *big.Int
}

// SignerPublicData contains the public values from the Signer (generated from
// its SignerPrivateData)
type SignerPublicData struct {
	// Q is the Signer Public Key
	Q *PublicKey // = skG
	R *Point     // = kG
}

// NewSigner returns a new SignerPrivateData with random D & K
func NewSigner() *SignerPrivateData {
	sk := NewPrivateKey()
	k := newRand()
	return &SignerPrivateData{
		D: sk,
		K: k,
	}
}

// PublicData returns the SignerPublicData from the SignerPrivateData
func (signer *SignerPrivateData) PublicData() *SignerPublicData {
	return &SignerPublicData{
		Q: signer.D.Public(), // Q = dG
		R: G.Mul(signer.K),   // R = kG
	}
}

// BlindSign performs the blind signature on the given mBlinded using
// SignerPrivateData values
func (signer *SignerPrivateData) BlindSign(mBlinded *big.Int) *big.Int {
	// TODO add pending checks
	// s' = d(m') + k
	sBlind := new(big.Int).Add(
		new(big.Int).Mul(signer.D.BigInt(), mBlinded),
		signer.K)
	return sBlind
}

// UserSecretData contains the secret values from the User (a, b, c) and the
// public F
type UserSecretData struct {
	A *big.Int
	B *big.Int
	C *big.Int

	F *Point // public
}

// Blind performs the blinding operation on m using SignerPublicData parameters
func Blind(m *big.Int, signer *SignerPublicData) (*big.Int, *UserSecretData) {
	u := &UserSecretData{}
	u.A = newRand()
	u.B = newRand()
	u.C = newRand()
	binv := new(big.Int).ModInverse(u.B, N)

	// F = b^-1 R + a b^-1 Q + c G
	bR := signer.R.Mul(binv)
	abinv := new(big.Int).Mul(u.A, binv)
	abinv = new(big.Int).Mod(abinv, N)
	abQ := signer.Q.Point().Mul(abinv)
	cG := G.Mul(u.C)
	u.F = bR.Add(abQ).Add(cG)
	// TODO check F==O

	r := new(big.Int).Mod(u.F.X, N)

	// m' = br(m)+a
	br := new(big.Int).Mul(u.B, r)
	brm := new(big.Int).Mul(br, m)
	mBlinded := new(big.Int).Add(brm, u.A)
	mBlinded = new(big.Int).Mod(mBlinded, N)
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
	// s = b^-1 s' + c
	binv := new(big.Int).ModInverse(u.B, N)
	bs := new(big.Int).Mul(binv, sBlind)
	s := new(big.Int).Add(bs, u.C)
	s = new(big.Int).Mod(s, N)

	return &Signature{
		S: s,
		F: u.F,
	}
}

// Verify checks the signature of the message m for the given PublicKey
func Verify(m *big.Int, signature *Signature, q *PublicKey) bool {
	// TODO add pending checks
	sG := G.Mul(signature.S) // sG

	r := new(big.Int).Mod(signature.F.X, N) // r = Fx mod N
	rm := new(big.Int).Mul(r, m)
	rm = new(big.Int).Mod(rm, N)
	rmQ := q.Point().Mul(rm)
	rmQF := rmQ.Add(signature.F) // rmQ + F

	// check sG == rmQ + F
	if bytes.Equal(sG.X.Bytes(), rmQF.X.Bytes()) &&
		bytes.Equal(sG.Y.Bytes(), rmQF.Y.Bytes()) {
		return true
	}
	return false
}
