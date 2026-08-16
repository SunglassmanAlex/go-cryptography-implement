package bn254util

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func PointFromScalar(s *big.Int) bn254.G1Affine {
	var p bn254.G1Affine
	p.ScalarMultiplicationBase(s)
	return p
}
