package blindsecp256k1

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
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
	sigB := sig.Bytes()
	sig2, err := NewSignatureFromBytes(sigB)
	assert.Nil(t, err)
	assert.Equal(t, sig, sig2)

	// signature can be verified with signer PublicKey
	verified := Verify(msg, sig, signerPubK)
	assert.True(t, verified)
}
