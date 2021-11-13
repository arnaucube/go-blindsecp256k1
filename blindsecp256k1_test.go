package blindsecp256k1

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO abstract the test to work with any curve, and be
// called from a test that testes all the tests with the
// main curves

func TestFlow(t *testing.T) {
	curv := btcec.S256()
	// signer: create new signer key pair
	sk := NewPrivateKey(curv)
	signerPubK := sk.Public(curv)

	// signer: when user requests new R parameter to blind a new msg,
	// create new signerR (public) with its secret k
	k, signerR := NewRequestParameters(curv)

	// user: blinds the msg using signer's R
	msg := new(big.Int).SetBytes([]byte("test"))
	msgBlinded, userSecretData, err := Blind(curv, msg, signerR)
	require.Nil(t, err)

	// signer: signs the blinded message using its private key & secret k
	sBlind, err := sk.BlindSign(curv, msgBlinded, k)
	require.Nil(t, err)

	// user: unblinds the blinded signature
	sig := Unblind(curv, sBlind, userSecretData)
	sigB := sig.Bytes()
	sig2, err := NewSignatureFromBytes(sigB)
	assert.Nil(t, err)
	assert.Equal(t, sig, sig2)

	// signature can be verified with signer PublicKey
	verified := Verify(curv, msg, sig, signerPubK)
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

func TestPointCompressDecompress(t *testing.T) {
	curv := btcec.S256()
	c := Curve{curv}

	G := &Point{
		X: curv.Gx,
		Y: curv.Gy,
	}
	p := &Point{
		X: curv.Gx,
		Y: curv.Gy,
	}
	b := p.Compress()
	assert.Equal(t,
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800",
		hex.EncodeToString(b[:]))
	p2, err := DecompressPoint(curv, b)
	require.Nil(t, err)
	assert.Equal(t, p, p2)

	for i := 2; i < 1000; i++ {
		p := c.Mul(G, big.NewInt(int64(i)))
		b := p.Compress()
		assert.Equal(t, 33, len(b))

		p2, err := DecompressPoint(curv, b)
		require.Nil(t, err)
		assert.Equal(t, p, p2)
	}
}

func TestSignatureCompressDecompress(t *testing.T) {
	curv := btcec.S256()
	c := Curve{curv}

	G := &Point{
		X: curv.Gx,
		Y: curv.Gy,
	}
	f := G
	sig := &Signature{
		S: big.NewInt(1),
		F: f,
	}
	b := sig.Compress()
	assert.Equal(t,
		"01000000000000000000000000000000000000000000000000000000000000007"+
			"9be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800",
		hex.EncodeToString(b[:]))
	sig2, err := DecompressSignature(curv, b)
	require.Nil(t, err)
	assert.Equal(t, sig, sig2)

	f = G
	P := curv.Params().P
	// Q = (P+1)/4
	Q := new(big.Int).Div(new(big.Int).Add(P,
		big.NewInt(1)), big.NewInt(4)) // nolint:gomnd
	sig = &Signature{
		S: Q,
		F: f,
	}
	b = sig.Compress()
	assert.Equal(t,
		"0cffffbfffffffffffffffffffffffffffffffffffffffffffffffffffffff3f7"+
			"9be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800",
		hex.EncodeToString(b[:]))
	sig2, err = DecompressSignature(curv, b)
	require.Nil(t, err)
	require.Equal(t, sig, sig2)

	for i := 2; i < 10; i++ {
		s := new(big.Int).Mod(new(big.Int).Mul(Q, big.NewInt(int64(i))), P)
		f := c.Mul(G, big.NewInt(int64(i)))
		sig := &Signature{
			S: s,
			F: f,
		}
		b := sig.Compress()
		assert.Equal(t, 65, len(b))

		sig2, err := DecompressSignature(curv, b)
		require.Nil(t, err)
		assert.Equal(t, sig, sig2)
	}
}

func BenchmarkCompressDecompress(b *testing.B) {
	curv := btcec.S256()
	c := Curve{curv}

	const n = 256
	var points [n]*Point
	var compPoints [n][33]byte
	G := &Point{
		X: curv.Gx,
		Y: curv.Gy,
	}

	for i := 0; i < n; i++ {
		points[i] = c.Mul(G, big.NewInt(int64(i)))
	}
	for i := 0; i < n; i++ {
		compPoints[i] = points[i].Compress()
	}

	b.Run("Compress", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = points[i%n].Compress()
		}
	})
	b.Run("DecompressPoint", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = DecompressPoint(curv, compPoints[i%n])
		}
	})
}
