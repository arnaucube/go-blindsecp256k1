package blindsecp256k1

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlow(t *testing.T) {
	// message to be signed
	msg := new(big.Int).SetBytes([]byte("test"))

	// create new signer
	signerPrivateData := NewSigner()
	signerPublicData := signerPrivateData.PublicData()

	// user blinds the msg
	msgBlinded, user := Blind(msg, signerPublicData)

	// signer signs the blinded message
	sBlind := signerPrivateData.BlindSign(msgBlinded)

	// user unblinds the blinded signature
	sig := Unblind(sBlind, msg, user)

	// signature can be verified with signer PublicKey (Q)
	verified := Verify(msg, sig, signerPublicData.Q)
	assert.True(t, verified)
}
