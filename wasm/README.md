# blindsecp256k1 wasm clientlib
[blindsecp256k1](https://github.com/arnaucube/go-blindsecp256k1) lib for browsers using go WASM.

## Wasm usage
To compile to wasm, inside the `wasm` directory, execute:
```
./build.sh
```

Add the file `wasm_exec.js` in the `webtest` directory:
```
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
```

To see the usage from javascript, check `index.js` file.
