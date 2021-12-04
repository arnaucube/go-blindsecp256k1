package blindsecp256k1

import (
	"fmt"
	"math/big"
)

// BytesUncompressed returns a byte array of length 64, with the X & Y
// coordinates of the Point encoded in little-endian.  [ X (32 bytes) | Y (32
// bytes)]
func (p *Point) BytesUncompressed() []byte {
	var b [64]byte
	copy(b[:32], swapEndianness(p.X.Bytes()))
	copy(b[32:], swapEndianness(p.Y.Bytes()))
	return b[:]
}

// NewPointFromBytesUncompressed returns a new *Point from a given byte array
// with length 64 which has encoded the point coordinates each one as 32 bytes
// in little-endian.
func NewPointFromBytesUncompressed(b []byte) (*Point, error) {
	if len(b) != 64 { //nolint:gomnd
		return nil, fmt.Errorf("Can not parse bytes to Point,"+
			" expected byte array of length %d, current %d",
			64, len(b))
	}
	p := &Point{}
	p.X = new(big.Int).SetBytes(swapEndianness(b[:32]))
	p.Y = new(big.Int).SetBytes(swapEndianness(b[32:]))
	return p, nil
}

// BytesUncompressed returns a byte array of length 64, with the X & Y
// coordinates of the PublicKey encoded in little-endian.
// [ X (32 bytes) | Y (32 bytes)]
func (pk *PublicKey) BytesUncompressed() []byte {
	return pk.Point().BytesUncompressed()
}

// NewPublicKeyFromBytesUncompressed returns a new *PublicKey from a given byte array with
// length 64 which has encoded the public key coordinates each one as 32 bytes
// in little-endian.
func NewPublicKeyFromBytesUncompressed(b []byte) (*PublicKey, error) {
	p, err := NewPointFromBytesUncompressed(b)
	if err != nil {
		return nil, err
	}
	pk := PublicKey(*p)
	return &pk, nil
}

// BytesUncompressed returns a byte array of length 96, with the S, F.X and F.Y
// coordinates of the Signature encoded in little-endian.
// [ S (32 bytes | F.X (32 bytes) | F.Y (32 bytes)]
func (sig *Signature) BytesUncompressed() []byte {
	var b [96]byte
	copy(b[:32], swapEndianness(sig.S.Bytes()))
	copy(b[32:96], sig.F.BytesUncompressed())
	return b[:]
}

// NewSignatureFromBytesUncompressed returns a new *Signature from a given byte array with
// length 96 which has encoded S and the F point coordinates each one as 32
// bytes in little-endian.
func NewSignatureFromBytesUncompressed(b []byte) (*Signature, error) {
	if len(b) != 96 { //nolint:gomnd
		return nil,
			fmt.Errorf("Can not parse bytes to Signature,"+
				" expected byte array of length %d, current %d",
				96, len(b))
	}
	s := new(big.Int).SetBytes(swapEndianness(b[:32]))
	f, err := NewPointFromBytesUncompressed(b[32:96])
	if err != nil {
		return nil, err
	}
	return &Signature{
		S: s,
		F: f,
	}, nil
}
