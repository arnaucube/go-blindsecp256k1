package blindsecp256k1

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBytesUncompressed(t *testing.T) {
	// Point
	p := &Point{
		X: big.NewInt(3),
		Y: big.NewInt(3),
	}
	b := p.BytesUncompressed()
	assert.Equal(t, "03000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(b)) //nolint:lll
	p2, err := NewPointFromBytesUncompressed(b)
	assert.Nil(t, err)
	assert.Equal(t, p, p2)

	p = G.Mul(big.NewInt(1234))
	b = p.BytesUncompressed()
	assert.Equal(t, "f258163f65f65865a79a4279e2ebabb5a57b85501dd4b381d1dc605c434876e34c308bd3f18f062d5cc07f34948ced82f9a76f9c3e65ae64f158412da8e92e6d", hex.EncodeToString(b)) //nolint:lll
	p2, err = NewPointFromBytesUncompressed(b)
	assert.Nil(t, err)
	assert.Equal(t, p, p2)

	// PublicKey
	pk := PublicKey(*p)
	b = pk.BytesUncompressed()
	assert.Equal(t, "f258163f65f65865a79a4279e2ebabb5a57b85501dd4b381d1dc605c434876e34c308bd3f18f062d5cc07f34948ced82f9a76f9c3e65ae64f158412da8e92e6d", hex.EncodeToString(b)) //nolint:lll
	pk2, err := NewPublicKeyFromBytesUncompressed(b)
	assert.Nil(t, err)
	assert.Equal(t, &pk, pk2)

	// Signature
	sig := Signature{
		S: big.NewInt(9876),
		F: p,
	}
	b = sig.BytesUncompressed()
	assert.Equal(t, "9426000000000000000000000000000000000000000000000000000000000000f258163f65f65865a79a4279e2ebabb5a57b85501dd4b381d1dc605c434876e34c308bd3f18f062d5cc07f34948ced82f9a76f9c3e65ae64f158412da8e92e6d", hex.EncodeToString(b)) //nolint:lll
	sig2, err := NewSignatureFromBytesUncompressed(b)
	assert.Nil(t, err)
	assert.Equal(t, &sig, sig2)

	// Signature with bigger values
	s, ok := new(big.Int).SetString("43744879514016998261043792362491545206150700367692876136431010903034023684055", 10) //nolint:lll
	require.True(t, ok)
	x, ok := new(big.Int).SetString("56183217574518331862027285308947626162625485037257226169003339923450551228164", 10) //nolint:lll
	require.True(t, ok)
	y, ok := new(big.Int).SetString("62825693913681695979055350889339417157462875026935818721506450621762231021976", 10) //nolint:lll
	require.True(t, ok)
	sig = Signature{
		S: s,
		F: &Point{X: x, Y: y},
	}
	b = sig.BytesUncompressed()
	assert.Equal(t, "d7a75050259cc06415f19bde5460a58325e3050806ba949d9ac9728b71b9b6600457ba001981781ed31acafed3d1e82c2ad53d08e3f293eab2f199ed0193367c98311f1894598c91f10fe415ba4a6d04e1351d07430631c7decdbbdb2615e68a", hex.EncodeToString(b)) //nolint:lll
	sig2, err = NewSignatureFromBytesUncompressed(b)
	assert.Nil(t, err)
	assert.Equal(t, &sig, sig2)
}
