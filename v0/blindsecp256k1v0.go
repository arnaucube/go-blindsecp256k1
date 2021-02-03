// Package blindsecp256k1v0 implements the Blind signature scheme explained at
// "An Efficient Blind Signature Scheme Based on the Elliptic Curve Discrete
// Logarithm Problem", by Morteza Nikooghadama & Ali Zakerolhosseini
// http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf
//
// LICENSE can be found at https://github.com/arnaucube/go-blindsecp256k1/blob/master/LICENSE
//
package blindsecp256k1v0

// WARNING: WIP code

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/arnaucube/go-blindsecp256k1"
)

// WIP
func newRand() *big.Int {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	bi := new(big.Int).SetBytes(b[:])
	return new(big.Int).Mod(bi, blindsecp256k1.N)
}

// PrivateKey represents the signer's private key
type PrivateKey big.Int

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
func (sk *PrivateKey) Public() *blindsecp256k1.PublicKey {
	Q := blindsecp256k1.G.Mul(sk.BigInt())
	pk := blindsecp256k1.PublicKey(*Q)
	return &pk
}

// NewRequestParameters returns a new random k (secret) & R (public) parameters
func NewRequestParameters() (*big.Int, *blindsecp256k1.Point) {
	k := newRand()
	return k, blindsecp256k1.G.Mul(k) // R = kG
}

// BlindSign performs the blind signature on the given mBlinded using
// SignerPrivateData values
func (sk *PrivateKey) BlindSign(mBlinded *big.Int, k *big.Int) *big.Int {
	// TODO add pending checks
	// s' = d(m') + k
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
	C *big.Int

	F *blindsecp256k1.Point // public
}

// Blind performs the blinding operation on m using SignerPublicData parameters
func Blind(m *big.Int, signerPubK *blindsecp256k1.PublicKey,
	signerR *blindsecp256k1.Point) (*big.Int, *UserSecretData) {
	u := &UserSecretData{}
	u.A = newRand()
	u.B = newRand()
	u.C = newRand()
	binv := new(big.Int).ModInverse(u.B, blindsecp256k1.N)

	// F = b^-1 R + a b^-1 Q + c G
	bR := signerR.Mul(binv)
	abinv := new(big.Int).Mul(u.A, binv)
	abinv = new(big.Int).Mod(abinv, blindsecp256k1.N)
	abQ := signerPubK.Point().Mul(abinv)
	cG := blindsecp256k1.G.Mul(u.C)
	u.F = bR.Add(abQ).Add(cG)
	// TODO check F==O

	r := new(big.Int).Mod(u.F.X, blindsecp256k1.N)

	// m' = br(m)+a
	br := new(big.Int).Mul(u.B, r)
	brm := new(big.Int).Mul(br, m)
	mBlinded := new(big.Int).Add(brm, u.A)
	mBlinded = new(big.Int).Mod(mBlinded, blindsecp256k1.N)
	return mBlinded, u
}

// Signature contains the signature values S & F
type Signature struct {
	S *big.Int
	F *blindsecp256k1.Point
}

// Unblind performs the unblinding operation of the blinded signature for the
// given and the UserSecretData
func Unblind(sBlind *big.Int, u *UserSecretData) *Signature {
	// s = b^-1 s' + c
	binv := new(big.Int).ModInverse(u.B, blindsecp256k1.N)
	bs := new(big.Int).Mul(binv, sBlind)
	s := new(big.Int).Add(bs, u.C)
	s = new(big.Int).Mod(s, blindsecp256k1.N)

	return &Signature{
		S: s,
		F: u.F,
	}
}

// Verify checks the signature of the message m for the given PublicKey
func Verify(m *big.Int, signature *Signature, q *blindsecp256k1.PublicKey) bool {
	// TODO add pending checks
	sG := blindsecp256k1.G.Mul(signature.S) // sG

	r := new(big.Int).Mod(signature.F.X, blindsecp256k1.N) // r = Fx mod N
	rm := new(big.Int).Mul(r, m)
	rm = new(big.Int).Mod(rm, blindsecp256k1.N)
	rmQ := q.Point().Mul(rm)
	rmQF := rmQ.Add(signature.F) // rmQ + F

	// check sG == rmQ + F
	if bytes.Equal(sG.X.Bytes(), rmQF.X.Bytes()) &&
		bytes.Equal(sG.Y.Bytes(), rmQF.Y.Bytes()) {
		return true
	}
	return false
}
