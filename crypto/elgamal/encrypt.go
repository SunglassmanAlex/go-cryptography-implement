package elgamal

import (
	"Implement/crypto/bn254util"
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func (pub *PublicKey) Encrypt(message bn254.G1Affine) (*Ciphertext, error) {
	if pub == nil {
		return nil, errors.New("nil public key")
	}
	k, err := bn254util.RandomNonZeroScalar()
	if err != nil {
		return nil, err
	}
	var shared, c1, c2 bn254.G1Affine
	shared.ScalarMultiplication(&pub.Point, k)
	c2.Add(&message, &shared)
	c1.ScalarMultiplicationBase(k)
	return &Ciphertext{C1: c1, C2: c2}, nil
}
