package blindsecp256k1

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
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

func TestHashMOddBytes(t *testing.T) {
	// This test is made with same values than
	// https://github.com/arnaucube/blindsecp256k1-js to ensure
	// compatibility
	mStr := "3024162961766929396601888431330224482373544644288322432261208139289299439809"
	m, ok := new(big.Int).SetString(mStr, 10)
	require.True(t, ok)
	mBytes := m.Bytes()

	hBytes := crypto.Keccak256(mBytes[3:])
	h := new(big.Int).SetBytes(hBytes)
	assert.Equal(t,
		"57523339312508913023232057765773019244858443678197951618720342803494056599369",
		h.String())

	hBytes = crypto.Keccak256(append(mBytes, []byte{0x12, 0x34}...))
	h = new(big.Int).SetBytes(hBytes)
	assert.Equal(t,
		"9697834584560956691445940439424778243200861871421750951058436814122640359156",
		h.String())
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
