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

	// signature can be verified with signer PublicKey
	verified := Verify(msg, sig, signerPubK)
	assert.True(t, verified)
}

// func TestPointCompressDecompress(t *testing.T) {
//         // x := big.NewInt(25)
//         // f := big.NewInt(1)
//         // fmt.Println("f", f)
//         // f = squareMul(f, x, true)
//         // fmt.Println("f", f)
//         // f = squareMul(f, x, true)
//         // fmt.Println("f", f)
//         // f = squareMul(f, x, true)
//         // fmt.Println("f", f)
//         // f = squareMul(f, x, true)
//         // fmt.Println("f", f)
//         // f = squareMul(f, x, true)
//         // require.Equal(t, "21684043449710088680149056017398834228515625", f.String())
//         // fmt.Println("f", f, x)
//         // f = squareMul(f, x, true)
//         // fmt.Println("f", f, x)
//         // require.Equal(t, "72482250313621475425650965409810619910529643899145444686122770647178269858429", f.String())
//         // f = squareMul(f, x, true)
//         // fmt.Println("f", f, x)
//         // f = squareMul(f, x, true)
//         // fmt.Println("f", f, x)
//
//         // sqrtQ
//         // r := sqrtQ(big.NewInt(25))
//         // assert.Equal(t, "115792089237316195423570985008687907853269984665640564039457584007908834671658", r.String())
//         fmt.Println(N)
//
//         //
//         // p := G.Mul(big.NewInt(1234))
//         p := G
//         // p := &Point{
//         //         X: big.NewInt(3),
//         //         Y: big.NewInt(3),
//         // }
//         fmt.Println("eX", p.X)
//         fmt.Println("eY", p.Y)
//         b := p.Compress()
//         // fmt.Println("hex", hex.EncodeToString(b[:]))
//
//         // var p2 *Point
//         // err := p2.Decompress(b)
//         p2, err := Decompress(b)
//         require.Nil(t, err)
//         assert.Equal(t, p, p2)
// }
