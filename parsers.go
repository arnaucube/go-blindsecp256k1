package blindsecp256k1

import (
	"encoding/json"
	"fmt"
	"math/big"
)

// swapEndianness swaps the order of the bytes in the slice.
func swapEndianness(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return o
}

// MarshalJSON implements the json marshaler for the Point
func (p Point) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: p.X.String(),
		Y: p.Y.String(),
	})
}

// UnmarshalJSON implements the json unmarshaler for the Point
func (p *Point) UnmarshalJSON(b []byte) error {
	aux := &struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{}
	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}
	x, ok := new(big.Int).SetString(aux.X, 10)
	if !ok {
		return fmt.Errorf("Can not parse Point.X %s", aux.X)
	}
	y, ok := new(big.Int).SetString(aux.Y, 10)
	if !ok {
		return fmt.Errorf("Can not parse Point.Y %s", aux.Y)
	}
	p.X = x
	p.Y = y
	return nil
}

// Bytes returns a byte array of length 64, with the X & Y coordinates of the
// Point encoded in little-endian.  [ X (32 bytes) | Y (32 bytes)]
func (p *Point) Bytes() []byte {
	var b [64]byte
	copy(b[:32], swapEndianness(p.X.Bytes()))
	copy(b[32:], swapEndianness(p.Y.Bytes()))
	return b[:]
}

// NewPointFromBytes returns a new *Point from a given byte array with length
// 64 which has encoded the point coordinates each one as 32 bytes in
// little-endian.
func NewPointFromBytes(b []byte) (*Point, error) {
	if len(b) != 64 { //nolint:gomnd
		return nil,
			fmt.Errorf("Can not parse bytes to Point, expected byte array of length %d, current %d",
				64, len(b))
	}
	p := &Point{}
	p.X = new(big.Int).SetBytes(swapEndianness(b[:32]))
	p.Y = new(big.Int).SetBytes(swapEndianness(b[32:]))
	return p, nil
}

// MarshalJSON implements the json marshaler for the PublicKey
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(pk.Point())
}

// UnmarshalJSON implements the json unmarshaler for the PublicKey
func (pk *PublicKey) UnmarshalJSON(b []byte) error {
	var point *Point
	err := json.Unmarshal(b, &point)
	if err != nil {
		return err
	}
	pk.X = point.X
	pk.Y = point.Y
	return nil
}

// Bytes returns a byte array of length 64, with the X & Y coordinates of the
// PublicKey encoded in little-endian.  [ X (32 bytes) | Y (32 bytes)]
func (pk *PublicKey) Bytes() []byte {
	return pk.Point().Bytes()
}

// NewPublicKeyFromBytes returns a new *PublicKey from a given byte array with
// length 64 which has encoded the public key coordinates each one as 32 bytes
// in little-endian.
func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
	p, err := NewPointFromBytes(b)
	if err != nil {
		return nil, err
	}
	pk := PublicKey(*p)
	return &pk, nil
}

// MarshalJSON implements the json marshaler for the Signature
func (sig Signature) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		S string `json:"s"`
		F struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"f"`
	}{
		S: sig.S.String(),
		F: struct {
			X string `json:"x"`
			Y string `json:"y"`
		}{
			X: sig.F.X.String(),
			Y: sig.F.Y.String(),
		},
	})
}

// UnmarshalJSON implements the json unmarshaler for the Signature
func (sig *Signature) UnmarshalJSON(b []byte) error {
	aux := &struct {
		S string `json:"s"`
		F struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"f"`
	}{}
	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}

	s, ok := new(big.Int).SetString(aux.S, 10)
	if !ok {
		return fmt.Errorf("Can not parse sig.S %s", aux.S)
	}
	sig.S = s

	x, ok := new(big.Int).SetString(aux.F.X, 10)
	if !ok {
		return fmt.Errorf("Can not parse sig.F.X %s", aux.F.X)
	}
	y, ok := new(big.Int).SetString(aux.F.Y, 10)
	if !ok {
		return fmt.Errorf("Can not parse sig.F.Y %s", aux.F.Y)
	}
	sig.F = &Point{}
	sig.F.X = x
	sig.F.Y = y
	return nil
}

// Bytes returns a byte array of length 96, with the S, F.X and F.Y coordinates
// of the Signature encoded in little-endian.
// [ S (32 bytes | F.X (32 bytes) | F.Y (32 bytes)]
func (sig *Signature) Bytes() []byte {
	var b [96]byte
	copy(b[:32], swapEndianness(sig.S.Bytes()))
	copy(b[32:96], sig.F.Bytes())
	return b[:]
}

// NewSignatureFromBytes returns a new *Signature from a given byte array with
// length 96 which has encoded S and the F point coordinates each one as 32
// bytes in little-endian.
func NewSignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != 96 { //nolint:gomnd
		return nil,
			fmt.Errorf("Can not parse bytes to Signature, expected byte array of length %d, current %d",
				96, len(b))
	}
	s := new(big.Int).SetBytes(swapEndianness(b[:32]))
	f, err := NewPointFromBytes(b[32:96])
	if err != nil {
		return nil, err
	}
	return &Signature{
		S: s,
		F: f,
	}, nil
}
