package blindsecp256k1

import (
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
	msgBlinded, userSecretData, err := Blind(msg, signerR)
	require.Nil(t, err)

	// signer: signs the blinded message using its private key & secret k
	sBlind, err := sk.BlindSign(msgBlinded, k)
	require.Nil(t, err)

	// user: unblinds the blinded signature
	sig := Unblind(sBlind, userSecretData)
	sigB := sig.Bytes()
	sig2, err := NewSignatureFromBytes(sigB)
	assert.Nil(t, err)
	assert.Equal(t, sig, sig2)

	// signature can be verified with signer PublicKey
	verified := Verify(msg, sig, signerPubK)
	assert.True(t, verified)
}

// func newBigIntWithBitLen(n int) *big.Int {
//         b := make([]byte, n/8)
//         for i := 0; i < len(b); i++ {
//                 b[i] = 255
//         }
//         bi := new(big.Int).SetBytes(b[:])
//         return bi
// }
//
// func TestMinBigIntBytesLen(t *testing.T) {
//         k := big.NewInt(1)
//         sk := PrivateKey(*k)
//
//         mBlinded := newBigIntWithBitLen(MinBigIntBytesLen)
//         require.Equal(t, MinBigIntBytesLen, mBlinded.BitLen())
//         _, err := sk.BlindSign(mBlinded, k)
//         assert.Nil(t, err)
//
//         mBlinded = new(big.Int).Div(mBlinded, big.NewInt(2))
//         require.Equal(t, MinBigIntBytesLen-1, mBlinded.BitLen())
//         _, err = sk.BlindSign(mBlinded, k)
//         assert.Equal(t, "mBlinded too small", err.Error())
// }
