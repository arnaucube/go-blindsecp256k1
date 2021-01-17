package blindsecp256k1

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlow(t *testing.T) {
	// signer: create new signer key pair
	sk := NewPrivateKey()
	signerPubK := sk.Public()

	// signer: when user requests new R parameter to blind a new msg,
	// create new signerR (public) with its secret k
	k, signerR := NewRequestParameters()

	// user: blinds the msg using signer's R
	msg := new(big.Int).SetBytes([]byte("test"))
	msgBlinded, userSecretData := Blind(msg, signerR)

	// signer: signs the blinded message using its private key & secret k
	sBlind := sk.BlindSign(msgBlinded, k)

	// user: unblinds the blinded signature
	sig := Unblind(sBlind, msg, userSecretData)

	// signature can be verified with signer PublicKey
	verified := Verify(msg, sig, signerPubK)
	assert.True(t, verified)
}

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
