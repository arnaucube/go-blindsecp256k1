#!/bin/sh

GOARCH=wasm GOOS=js go build -o blindsecp256k1.wasm blindsecp256k1-wasm.go
mv blindsecp256k1.wasm webtest/blindsecp256k1.wasm
