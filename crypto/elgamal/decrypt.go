package elgamal

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func (priv *PrivateKey) Decrypt(ct *Ciphertext) (bn254.G1Affine, error) {
	var message bn254.G1Affine
	if priv == nil || priv.X == nil {
		return message, errors.New("nil private key")
	}
	if ct == nil {
		return message, errors.New("nil ciphertext")
	}
	var shared bn254.G1Affine
	shared.ScalarMultiplication(&ct.C1, priv.X)
	message.Sub(&ct.C2, &shared)
	return message, nil
}
