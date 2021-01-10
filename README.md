# go-blindsecp256k1 [![GoDoc](https://godoc.org/github.com/arnaucube/go-blindsecp256k1?status.svg)](https://godoc.org/github.com/arnaucube/go-blindsecp256k1) [![Go Report Card](https://goreportcard.com/badge/github.com/arnaucube/go-blindsecp256k1)](https://goreportcard.com/report/github.com/arnaucube/go-blindsecp256k1) [![Test](https://github.com/arnaucube/go-blindsecp256k1/workflows/Test/badge.svg)](https://github.com/arnaucube/go-blindsecp256k1/actions?query=workflow%3ATest)

Blind signature over [secp256k1](https://en.bitcoin.it/wiki/Secp256k1), based on *"[An Efficient Blind Signature Scheme Based on the Elliptic Curve Discrete Logarithm Problem](http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf)"* paper.

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

## WASM usage
WASM wrappers for browser usage can be found at the [wasm](https://github.com/arnaucube/go-blindsecp256k1/tree/master/wasm/) directory with an example in html&js.
