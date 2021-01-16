# go-blindsecp256k1 [![GoDoc](https://godoc.org/github.com/arnaucube/go-blindsecp256k1?status.svg)](https://godoc.org/github.com/arnaucube/go-blindsecp256k1) [![Go Report Card](https://goreportcard.com/badge/github.com/arnaucube/go-blindsecp256k1)](https://goreportcard.com/report/github.com/arnaucube/go-blindsecp256k1) [![Test](https://github.com/arnaucube/go-blindsecp256k1/workflows/Test/badge.svg)](https://github.com/arnaucube/go-blindsecp256k1/actions?query=workflow%3ATest)

Blind signature over [secp256k1](https://en.bitcoin.it/wiki/Secp256k1), based on *"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem](https://sci-hub.do/10.1109/ICCKE.2013.6682844)"* paper by Hamid Mala & Nafiseh Nezhadansari.

**WARNING**: this repo is experimental, do not use in production.

## Usage

```go
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
```

## WASM usage
WASM wrappers for browser usage can be found at the [wasm](https://github.com/arnaucube/go-blindsecp256k1/tree/master/wasm/) directory with an example in html&js.
