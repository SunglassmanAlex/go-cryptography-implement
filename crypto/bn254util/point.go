package bn254util

import (
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func PointFromScalar(s *big.Int) bn254.G1Affine {
	var p bn254.G1Affine
	p.ScalarMultiplicationBase(s)
	return p
}

func KeyFromPoint(p *bn254.G1Affine) []byte {
	raw := p.RawBytes()
	h := sha256.Sum256(raw[:])
	return h[:]
}
