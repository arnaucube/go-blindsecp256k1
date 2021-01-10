package blindsecp256k1

// WARNING: WIP code

import (
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
