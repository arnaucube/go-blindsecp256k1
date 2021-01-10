package main

import (
	"blindsecp256k1"
	"fmt"
	"math/big"
	"syscall/js"
)

func main() {
	c := make(chan struct{}, 0)
	println("WASM blindsecp256k1 initialized")
	registerCallbacks()
	<-c
}

func registerCallbacks() {
	js.Global().Set("blind", js.FuncOf(blind))
	js.Global().Set("unblind", js.FuncOf(unblind))
}

func stringToBigInt(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Errorf("error parsing string *big.Int: %s", s))
	}
	return b
}

func blind(this js.Value, values []js.Value) interface{} {
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

	signer := &blindsecp256k1.SignerPublicData{signerQ, signerR}
	mBlinded, user := blindsecp256k1.Blind(m, signer)

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

func unblind(this js.Value, values []js.Value) interface{} {
	sBlindStr := values[0].String()
	mStr := values[1].String()
	uBStr := values[2].String()
	uCStr := values[3].String()
	uFxStr := values[4].String()
	uFyStr := values[5].String()

	sBlind := stringToBigInt(sBlindStr)
	m := stringToBigInt(mStr)
	uB := stringToBigInt(uBStr)
	uC := stringToBigInt(uCStr)
	uFx := stringToBigInt(uFxStr)
	uFy := stringToBigInt(uFyStr)

	uF := &blindsecp256k1.Point{
		X: uFx,
		Y: uFy,
	}

	u := &blindsecp256k1.UserSecretData{
		// A not needed to Unblind
		B: uB,
		C: uC,
		F: uF,
	}

	sig := blindsecp256k1.Unblind(sBlind, m, u)

	r := make(map[string]interface{})
	r["s"] = sig.S.String()
	r["fx"] = sig.F.X.String()
	r["fy"] = sig.F.Y.String()
	return r
}
