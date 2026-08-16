package bn254util

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func RandomNonZeroScalar() (*big.Int, error) {
	for {
		x, err := rand.Int(rand.Reader, fr.Modulus())
		if err != nil {
			return nil, err
		}
		if x.Sign() != 0 {
			return x, nil
		}
	}
}
