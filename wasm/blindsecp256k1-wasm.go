package main

import (
	"fmt"
	"math/big"
	"syscall/js"

	"github.com/arnaucube/go-blindsecp256k1"

	blindsecp256k1v0 "github.com/arnaucube/go-blindsecp256k1/v0"
)

func main() {
	c := make(chan struct{}, 0)
	println("WASM blindsecp256k1 initialized")
	registerCallbacks()
	<-c
}

func registerCallbacks() {
	js.Global().Set("wasmReady", js.FuncOf(ready))

	// blindv0 & unblindv0 uses:
	// http://www.isecure-journal.com/article_39171_47f9ec605dd3918c2793565ec21fcd7a.pdf
	js.Global().Set("wasmBlindv0", js.FuncOf(blindv0))
	js.Global().Set("wasmUnblindv0", js.FuncOf(unblindv0))
	js.Global().Set("wasmVerifyv0", js.FuncOf(verifyv0))

	// blind & unblind uses: https://sci-hub.do/10.1109/ICCKE.2013.6682844
	js.Global().Set("wasmBlind", js.FuncOf(blind))
	js.Global().Set("wasmUnblind", js.FuncOf(unblind))
	js.Global().Set("wasmVerify", js.FuncOf(verify))
}

func stringToBigInt(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Errorf("error parsing string *big.Int: %s", s))
	}
	return b
}

func ready(this js.Value, values []js.Value) interface{} {
	return "ready"
}

func blindv0(this js.Value, values []js.Value) interface{} {
	mStr := values[0].String()
	signerQxStr := values[1].String()
	signerQyStr := values[2].String()
	signerRxStr := values[3].String()
	signerRyStr := values[4].String()

	m := stringToBigInt(mStr)
	signerQx := stringToBigInt(signerQxStr)
	signerQy := stringToBigInt(signerQyStr)
	signerRx := stringToBigInt(signerRxStr)
	signerRy := stringToBigInt(signerRyStr)

	signerQ := &blindsecp256k1.PublicKey{
		X: signerQx,
		Y: signerQy,
	}
	signerR := &blindsecp256k1.Point{
		X: signerRx,
		Y: signerRy,
	}

	mBlinded, user, err := blindsecp256k1v0.Blind(m, signerQ, signerR)
	if err != nil {
		panic(err)
	}

	r := make(map[string]interface{})
	r["mBlinded"] = mBlinded.String()
	r["uA"] = user.A.String()
	r["uB"] = user.B.String()
	r["uC"] = user.C.String()
	r["uC"] = user.C.String()
	r["uFx"] = user.F.X.String()
	r["uFy"] = user.F.Y.String()
	return r
}

func unblindv0(this js.Value, values []js.Value) interface{} {
	sBlindStr := values[0].String()
	uBStr := values[1].String()
	uCStr := values[2].String()
	uFxStr := values[3].String()
	uFyStr := values[4].String()

	sBlind := stringToBigInt(sBlindStr)
	uB := stringToBigInt(uBStr)
	uC := stringToBigInt(uCStr)
	uFx := stringToBigInt(uFxStr)
	uFy := stringToBigInt(uFyStr)

	uF := &blindsecp256k1.Point{
		X: uFx,
		Y: uFy,
	}

	u := &blindsecp256k1v0.UserSecretData{
		// A not needed to Unblind
		B: uB,
		C: uC,
		F: uF,
	}

	sig := blindsecp256k1v0.Unblind(sBlind, u)

	r := make(map[string]interface{})
	r["s"] = sig.S.String()
	r["fx"] = sig.F.X.String()
	r["fy"] = sig.F.Y.String()
	return r
}

func verifyv0(this js.Value, values []js.Value) interface{} {
	mStr := values[0].String()
	sigSStr := values[1].String()
	sigFxStr := values[2].String()
	sigFyStr := values[3].String()
	qxStr := values[4].String()
	qyStr := values[5].String()

	m := stringToBigInt(mStr)
	sigS := stringToBigInt(sigSStr)
	sigFx := stringToBigInt(sigFxStr)
	sigFy := stringToBigInt(sigFyStr)
	qx := stringToBigInt(qxStr)
	qy := stringToBigInt(qyStr)

	q := &blindsecp256k1.PublicKey{
		X: qx,
		Y: qy,
	}
	sig := &blindsecp256k1.Signature{
		S: sigS,
		F: &blindsecp256k1.Point{
			X: sigFx,
			Y: sigFy,
		},
	}
	verified := blindsecp256k1.Verify(m, sig, q)

	r := verified
	return r
}

func blind(this js.Value, values []js.Value) interface{} {
	mStr := values[0].String()
	signerRxStr := values[1].String()
	signerRyStr := values[2].String()

	m := stringToBigInt(mStr)
	signerRx := stringToBigInt(signerRxStr)
	signerRy := stringToBigInt(signerRyStr)

	signerR := &blindsecp256k1.Point{
		X: signerRx,
		Y: signerRy,
	}

	mBlinded, user, err := blindsecp256k1.Blind(m, signerR)
	if err != nil {
		panic(err)
	}

	r := make(map[string]interface{})
	r["mBlinded"] = mBlinded.String()
	r["uA"] = user.A.String()
	r["uB"] = user.B.String()
	r["uFx"] = user.F.X.String()
	r["uFy"] = user.F.Y.String()
	return r
}

func unblind(this js.Value, values []js.Value) interface{} {
	sBlindStr := values[0].String()
	uAStr := values[1].String()
	uBStr := values[2].String()
	uFxStr := values[3].String()
	uFyStr := values[4].String()

	sBlind := stringToBigInt(sBlindStr)
	uA := stringToBigInt(uAStr)
	uB := stringToBigInt(uBStr)
	uFx := stringToBigInt(uFxStr)
	uFy := stringToBigInt(uFyStr)

	uF := &blindsecp256k1.Point{
		X: uFx,
		Y: uFy,
	}

	u := &blindsecp256k1.UserSecretData{
		A: uA,
		B: uB,
		F: uF,
	}

	sig := blindsecp256k1.Unblind(sBlind, u)

	r := make(map[string]interface{})
	r["s"] = sig.S.String()
	r["fx"] = sig.F.X.String()
	r["fy"] = sig.F.Y.String()
	return r
}

func verify(this js.Value, values []js.Value) interface{} {
	mStr := values[0].String()
	sigSStr := values[1].String()
	sigFxStr := values[2].String()
	sigFyStr := values[3].String()
	qxStr := values[4].String()
	qyStr := values[5].String()

	m := stringToBigInt(mStr)
	sigS := stringToBigInt(sigSStr)
	sigFx := stringToBigInt(sigFxStr)
	sigFy := stringToBigInt(sigFyStr)
	qx := stringToBigInt(qxStr)
	qy := stringToBigInt(qyStr)

	q := &blindsecp256k1.PublicKey{
		X: qx,
		Y: qy,
	}
	sig := &blindsecp256k1.Signature{
		S: sigS,
		F: &blindsecp256k1.Point{
			X: sigFx,
			Y: sigFy,
		},
	}
	verified := blindsecp256k1.Verify(m, sig, q)

	r := verified
	return r
}
