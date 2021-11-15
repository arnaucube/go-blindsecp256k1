package blindsecp256k1v0

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlow(t *testing.T) {
	// signer: create new signer key pair
	sk, err := NewPrivateKey()
	require.Nil(t, err)
	signerPubK := sk.Public()

	// signer: when user requests new R parameter to blind a new msg,
	// create new signerR (public) with its secret k
	k, signerR, err := NewRequestParameters()
	require.Nil(t, err)

	// user: blinds the msg using signer's R
	msg := new(big.Int).SetBytes([]byte("test"))
	msgBlinded, userSecretData, err := Blind(msg, signerPubK, signerR)
	require.Nil(t, err)

	// signer: signs the blinded message using its private key & secret k
	sBlind := sk.BlindSign(msgBlinded, k)

	// user: unblinds the blinded signature
	sig := Unblind(sBlind, userSecretData)

	// signature can be verified with signer PublicKey (Q)
	verified := Verify(msg, sig, signerPubK)
	assert.True(t, verified)
}
