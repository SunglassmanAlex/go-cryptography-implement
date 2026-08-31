package elgamal

import (
	"Implement/crypto/bn254util"
	"Implement/crypto/ot"
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

func (priv *PrivateKey) DecryptBytes(ct *HybridCiphertext) ([]byte, error) {
	var shared bn254.G1Affine
	shared.ScalarMultiplication(&ct.C1, priv.X)
	key := bn254util.KeyFromPoint(&shared)
	msg := ot.XorBytes(ct.Cipher, key)
	return msg, nil
}
