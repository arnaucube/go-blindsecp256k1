package blindsecp256k1

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalers(t *testing.T) {
	// Point
	p := G.Mul(big.NewInt(1234))
	b, err := json.Marshal(p)
	require.Nil(t, err)
	assert.Equal(t,
		`{"x":"102884003323827292915668239759940053105992008087520207150474896054185180420338","y":"49384988101491619794462775601349526588349137780292274540231125201115197157452"}`, //nolint:lll
		string(b))

	var p2 *Point
	err = json.Unmarshal(b, &p2)
	require.Nil(t, err)
	assert.Equal(t, p, p2)

	// PublicKey
	pk := PublicKey(*p)
	b, err = json.Marshal(pk)
	require.Nil(t, err)
	assert.Equal(t,
		`{"x":"102884003323827292915668239759940053105992008087520207150474896054185180420338","y":"49384988101491619794462775601349526588349137780292274540231125201115197157452"}`, //nolint:lll
		string(b))

	var pk2 PublicKey
	err = json.Unmarshal(b, &pk2)
	require.Nil(t, err)
	assert.Equal(t, pk, pk2)

	// Signature
	sig := Signature{
		S: big.NewInt(9876),
		F: p,
	}
	b, err = json.Marshal(sig)
	require.Nil(t, err)
	assert.Equal(t,
		`{"s":"9876","f":{"x":"102884003323827292915668239759940053105992008087520207150474896054185180420338","y":"49384988101491619794462775601349526588349137780292274540231125201115197157452"}}`, //nolint:lll
		string(b))

	var sig2 Signature
	err = json.Unmarshal(b, &sig2)
	require.Nil(t, err)
	assert.Equal(t, sig, sig2)
}

func TestBytes(t *testing.T) {
	// Point
	p := &Point{
		X: big.NewInt(3),
		Y: big.NewInt(3),
	}
	b := p.Bytes()
	assert.Equal(t, "03000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(b)) //nolint:lll
	p2, err := NewPointFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, p, p2)

	p = G.Mul(big.NewInt(1234))
	b = p.Bytes()
	assert.Equal(t, "f258163f65f65865a79a4279e2ebabb5a57b85501dd4b381d1dc605c434876e34c308bd3f18f062d5cc07f34948ced82f9a76f9c3e65ae64f158412da8e92e6d", hex.EncodeToString(b)) //nolint:lll
	p2, err = NewPointFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, p, p2)

	// PublicKey
	pk := PublicKey(*p)
	b = pk.Bytes()
	assert.Equal(t, "f258163f65f65865a79a4279e2ebabb5a57b85501dd4b381d1dc605c434876e34c308bd3f18f062d5cc07f34948ced82f9a76f9c3e65ae64f158412da8e92e6d", hex.EncodeToString(b)) //nolint:lll
	pk2, err := NewPublicKeyFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, &pk, pk2)

	// Signature
	sig := Signature{
		S: big.NewInt(9876),
		F: p,
	}
	b = sig.Bytes()
	assert.Equal(t, "9426000000000000000000000000000000000000000000000000000000000000f258163f65f65865a79a4279e2ebabb5a57b85501dd4b381d1dc605c434876e34c308bd3f18f062d5cc07f34948ced82f9a76f9c3e65ae64f158412da8e92e6d", hex.EncodeToString(b)) //nolint:lll
	sig2, err := NewSignatureFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, &sig, sig2)
}
