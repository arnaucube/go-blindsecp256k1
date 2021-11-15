# go-blindsecp256k1 [![GoDoc](https://godoc.org/github.com/arnaucube/go-blindsecp256k1?status.svg)](https://godoc.org/github.com/arnaucube/go-blindsecp256k1) [![Go Report Card](https://goreportcard.com/badge/github.com/arnaucube/go-blindsecp256k1)](https://goreportcard.com/report/github.com/arnaucube/go-blindsecp256k1) [![Test](https://github.com/arnaucube/go-blindsecp256k1/workflows/Test/badge.svg)](https://github.com/arnaucube/go-blindsecp256k1/actions?query=workflow%3ATest)

Blind signature over [secp256k1](https://en.bitcoin.it/wiki/Secp256k1), based on *"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem](https://sci-hub.st/10.1109/iccke.2013.6682844)"* paper by Hamid Mala & Nafiseh Nezhadansari.

**WARNING**: this repo is experimental, do not use in production.

The implementation of this repo is compatible with https://github.com/arnaucube/blindsecp256k1-js

## Usage

```go
import (
	[...]
	"github.com/arnaucube/go-blindsecp256k1"
)

[...]
// errors are not handled for simplicity of the example

// signer: create new signer key pair
sk, _ := blindsecp256k1.NewPrivateKey()
signerPubK := sk.Public()

// signer: when user requests new R parameter to blind a new msg,
// create new signerR (public) with its secret k
k, signerR, _ := blindsecp256k1.NewRequestParameters()

// user: blinds the msg using signer's R
msg := new(big.Int).SetBytes([]byte("test"))
msgBlinded, userSecretData, _ := blindsecp256k1.Blind(msg, signerR)

// signer: signs the blinded message using its private key & secret k
sBlind, _ := sk.BlindSign(msgBlinded, k)

// user: unblinds the blinded signature
sig := blindsecp256k1.Unblind(sBlind, userSecretData)

// signature can be verified with signer PublicKey
verified := blindsecp256k1.Verify(msg, sig, signerPubK)
assert.True(t, verified)
```

Compression & decompression (allows to compress a point & public key (64 bytes) into 33 bytes, and a signature (96 bytes) into 65 bytes):
```go
p := blindsecp256k1.G // take the generator point as an example

// also, instead from G, we can start from a PublicKey, which can be converted
// into a Point with
p = pk.Point()

// compress point
b := p.Compress()
fmt.Println(hex.EncodeToString(b[:]))

// decompress point (recovering the original point)
p2, _ := blindsecp256k1.DecompressPoint(b)
assert.Equal(t, p, p2)


// compress signature
b = sig.Compress()
fmt.Println(hex.EncodeToString(b[:])) // 65 bytes

// decompress signature
sig2, _ := DecompressSignature(b)
assert.Equal(t, sig, sig2)
```

## WASM usage
WASM wrappers for browser usage can be found at the [wasm](https://github.com/arnaucube/go-blindsecp256k1/tree/master/wasm/) directory with an example in html&js.
