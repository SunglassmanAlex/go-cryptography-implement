package elgamal

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type PrivateKey struct {
	X *big.Int
}

type PublicKey struct {
	Point bn254.G1Affine
}

type Ciphertext struct {
	C1 bn254.G1Affine
	C2 bn254.G1Affine
}
