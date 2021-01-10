// Package blindsecp256k1 implements the Blind signature scheme explained at
// http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf
//
// LICENSE can be found at https://github.com/arnaucube/go-blindsecp256k1/blob/master/LICENSE
package blindsecp256k1

// WARNING: WIP code

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

var (
	G *Point = &Point{
		X: secp256k1.S256().Gx,
		Y: secp256k1.S256().Gy,
	}

	N *big.Int = secp256k1.S256().N
)

func (p *Point) Add(q *Point) *Point {
	x, y := secp256k1.S256().Add(p.X, p.Y, q.X, q.Y)
	return &Point{
		X: x,
		Y: y,
	}
}

func (p *Point) Mul(scalar *big.Int) *Point {
	x, y := secp256k1.S256().ScalarMult(p.X, p.Y, scalar.Bytes())
	return &Point{
		X: x,
		Y: y,
	}
}

func newRand() *big.Int {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	bi := new(big.Int).SetBytes(b[:])
	return new(big.Int).Mod(bi, N)
}

type PrivateKey big.Int
type PublicKey Point

func NewPrivateKey() *PrivateKey {
	k := newRand()
	sk := PrivateKey(*k)
	return &sk
}

func (sk *PrivateKey) BigInt() *big.Int {
	return (*big.Int)(sk)
}

func (sk *PrivateKey) Public() *PublicKey {
	Q := G.Mul(sk.BigInt())
	pk := PublicKey(*Q)
	return &pk
}

func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

type SignerPrivateData struct {
	d *PrivateKey
	k *big.Int
}
type SignerPublicData struct {
	// Q is the Signer Public Key
	Q *PublicKey // = skG
	R *Point     // = kG
}

func NewSigner() *SignerPrivateData {
	sk := NewPrivateKey()
	k := newRand()
	return &SignerPrivateData{
		d: sk,
		k: k,
	}
}

func (signer *SignerPrivateData) PublicData() *SignerPublicData {
	return &SignerPublicData{
		Q: signer.d.Public(), // Q = dG
		R: G.Mul(signer.k),   // R = kG
	}
}

func (signer *SignerPrivateData) BlindSign(mBlinded *big.Int) *big.Int {
	// TODO add pending checks
	// s' = d(m') + k
	sBlind := new(big.Int).Add(
		new(big.Int).Mul(signer.d.BigInt(), mBlinded),
		signer.k)
	return sBlind
}

type UserSecretData struct {
	a *big.Int
	b *big.Int
	c *big.Int

	F *Point // public
}

func Blind(m *big.Int, signer *SignerPublicData) (*big.Int, *UserSecretData) {
	u := &UserSecretData{}
	u.a = newRand()
	u.b = newRand()
	u.c = newRand()
	binv := new(big.Int).ModInverse(u.b, N)

	// F = b^-1 R + a b^-1 Q + c G
	bR := signer.R.Mul(binv)
	abinv := new(big.Int).Mul(u.a, binv)
	abinv = new(big.Int).Mod(abinv, N)
	abQ := signer.Q.Point().Mul(abinv)
	cG := G.Mul(u.c)
	u.F = bR.Add(abQ).Add(cG)
	// TODO check F==O

	r := new(big.Int).Mod(u.F.X, N)

	// m' = br(m)+a
	br := new(big.Int).Mul(u.b, r)
	brm := new(big.Int).Mul(br, m)
	mBlinded := new(big.Int).Add(brm, u.a)
	mBlinded = new(big.Int).Mod(mBlinded, N)
	return mBlinded, u
}

type Signature struct {
	S *big.Int
	F *Point
}

func Unblind(sBlind, m *big.Int, u *UserSecretData) *Signature {
	// s = b^-1 s' + c
	binv := new(big.Int).ModInverse(u.b, N)
	bs := new(big.Int).Mul(binv, sBlind)
	s := new(big.Int).Add(bs, u.c)
	s = new(big.Int).Mod(s, N)

	return &Signature{
		S: s,
		F: u.F,
	}
}

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
