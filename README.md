# go-blindsecp256k1
Blind signature over [secp256k1](https://en.bitcoin.it/wiki/Secp256k1), based on *"[An Efficient Blind Signature Scheme Based on the Elliptic CurveDiscrete Logarithm Problem](http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf)"* paper.

**WARNING**: this repo is experimental, do not use in production.

## Usage

```go
// message to be signed
msg := new(big.Int).SetBytes([]byte("test"))

// create new signer
signerPrivateData := blindsecp256k1.NewSigner()
signerPublicData := signerPrivateData.PublicData()

// user blinds the msg
msgBlinded, user := blindsecp256k1.Blind(msg, signerPublicData)

// signer signs the blinded message
sBlind := signerPrivateData.BlindSign(msgBlinded)

// user unblinds the blinded signature
sig := blindsecp256k1.Unblind(sBlind, msg, user)

// signature can be verified with signer PublicKey
verified := blindsecp256k1.Verify(msg, sig, signerPublicData.Q)
assert.True(t, verified)
```
