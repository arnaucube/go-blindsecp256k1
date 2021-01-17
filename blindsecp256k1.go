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
	"encoding/json"
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

// MarshalJSON implements the json marshaler for the Point
func (p Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: p.X.String(),
		Y: p.Y.String(),
	})
}

// UnmarshalJSON implements the json unmarshaler for the Point
func (p *Point) UnmarshalJSON(b []byte) error {
	aux := &struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{}
	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}
	x, ok := new(big.Int).SetString(aux.X, 10)
	if !ok {
		return fmt.Errorf("Can not parse Point.X %s", aux.X)
	}
	y, ok := new(big.Int).SetString(aux.Y, 10)
	if !ok {
		return fmt.Errorf("Can not parse Point.Y %s", aux.Y)
	}
	p.X = x
	p.Y = y
	return nil
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

// MarshalJSON implements the json marshaler for the PublicKey
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(pk.Point())
}

// UnmarshalJSON implements the json unmarshaler for the PublicKey
func (pk *PublicKey) UnmarshalJSON(b []byte) error {
	var point *Point
	err := json.Unmarshal(b, &point)
	if err != nil {
		return err
	}
	pk.X = point.X
	pk.Y = point.Y
	return nil
}

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

// MarshalJSON implements the json marshaler for the Signature
func (sig Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		S string `json:"s"`
		F struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"f"`
	}{
		S: sig.S.String(),
		F: struct {
			X string `json:"x"`
			Y string `json:"y"`
		}{
			X: sig.F.X.String(),
			Y: sig.F.Y.String(),
		},
	})
}

// UnmarshalJSON implements the json unmarshaler for the Signature
func (sig *Signature) UnmarshalJSON(b []byte) error {
	aux := &struct {
		S string `json:"s"`
		F struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"f"`
	}{}
	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}

	s, ok := new(big.Int).SetString(aux.S, 10)
	if !ok {
		return fmt.Errorf("Can not parse sig.S %s", aux.S)
	}
	sig.S = s

	x, ok := new(big.Int).SetString(aux.F.X, 10)
	if !ok {
		return fmt.Errorf("Can not parse sig.F.X %s", aux.F.X)
	}
	y, ok := new(big.Int).SetString(aux.F.Y, 10)
	if !ok {
		return fmt.Errorf("Can not parse sig.F.Y %s", aux.F.Y)
	}
	sig.F = &Point{}
	sig.F.X = x
	sig.F.Y = y
	return nil
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
