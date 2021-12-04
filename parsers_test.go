package blindsecp256k1

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
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
	p := G.Mul(big.NewInt(3))
	b := p.Bytes()
	assert.Equal(t, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f900", hex.EncodeToString(b)) //nolint:lll
	p2, err := NewPointFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, p, p2)

	p = G.Mul(big.NewInt(1234))
	b = p.Bytes()
	assert.Equal(t, "e37648435c60dcd181b3d41d50857ba5b5abebe279429aa76558f6653f1658f200", hex.EncodeToString(b)) //nolint:lll
	p2, err = NewPointFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, p, p2)

	// PublicKey
	pk := PublicKey(*p)
	b = pk.Bytes()
	assert.Equal(t, "e37648435c60dcd181b3d41d50857ba5b5abebe279429aa76558f6653f1658f200", hex.EncodeToString(b)) //nolint:lll
	pk2, err := NewPublicKeyFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, &pk, pk2)

	// Signature
	sig := Signature{
		S: big.NewInt(9876),
		F: p,
	}
	b = sig.Bytes()
	assert.Equal(t, "9426000000000000000000000000000000000000000000000000000000000000e37648435c60dcd181b3d41d50857ba5b5abebe279429aa76558f6653f1658f200", hex.EncodeToString(b)) //nolint:lll
	sig2, err := NewSignatureFromBytes(b)
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
	b = sig.Bytes()
	assert.Equal(t, "d7a75050259cc06415f19bde5460a58325e3050806ba949d9ac9728b71b9b6607c369301ed99f1b2ea93f2e3083dd52a2ce8d1d3feca1ad31e78811900ba570400", hex.EncodeToString(b)) //nolint:lll
	sig2, err = NewSignatureFromBytes(b)
	assert.Nil(t, err)
	assert.Equal(t, &sig, sig2)
}

func TestImportECDSApubKey(t *testing.T) {
	// Generate an ECDSA key
	k, err := crypto.GenerateKey()
	assert.Nil(t, err)
	// Import the ECDSA Public key bytes into a PublicKey type
	pk, err := NewPublicKeyFromECDSA(crypto.FromECDSAPub(&k.PublicKey))
	assert.Nil(t, err)
	// Set the ECDSA Private key point as a blindsecp256k1 PrivateKey type
	bk := PrivateKey(*k.D)
	// Compare both public keys
	assert.Equal(t, bk.Public().Bytes(), pk.Bytes())
}
